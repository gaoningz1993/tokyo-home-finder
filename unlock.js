(() => {
 'use strict';
 const form = document.querySelector('#unlock-form');
 const passwordInput = document.querySelector('#access-password');
 const button = form.querySelector('button');
 const status = document.querySelector('#unlock-status');
 const fromBase64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));

 async function decrypt(bundle, password) {
  if (bundle.version !== 1 || bundle.iterations !== 600000) throw new Error('Unsupported bundle');
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({
   name: 'PBKDF2', salt: fromBase64(bundle.salt), iterations: bundle.iterations, hash: 'SHA-256'
  }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(bundle.iv) }, key, fromBase64(bundle.ciphertext));
  return JSON.parse(new TextDecoder().decode(plaintext));
 }

 function loadLeaflet() {
  return new Promise((resolve, reject) => {
   const script = document.createElement('script');
   script.src = 'assets/leaflet.js';
   script.onload = resolve;
   script.onerror = reject;
   document.head.append(script);
  });
 }

 async function prepareStyles(head) {
  const styles = Array.from(head.querySelectorAll('link[rel~="stylesheet"]'), link => ({
   link, media: link.getAttribute('media')
  }));
  try {
   await Promise.all(styles.map(({ link }) => new Promise((resolve, reject) => {
    link.addEventListener('load', resolve, { once: true });
    link.addEventListener('error', reject, { once: true });
    link.media = 'not all';
    document.head.append(link);
   })));
  } catch (error) {
   for (const { link } of styles) link.remove();
   throw error;
  }
  return styles;
 }

 async function mount(payload) {
  const page = new DOMParser().parseFromString(payload.html, 'text/html');
  page.querySelectorAll('script').forEach(script => script.remove());
  const nextHead = document.importNode(page.head, true);
  const nextBody = document.importNode(page.body, true);
  const styles = await prepareStyles(nextHead);
  // Leaflet reads the map's position and dimensions on startup.
  const loaded = new Set(styles.map(({ link }) => link));
  for (const child of [...document.head.childNodes]) {
   if (!loaded.has(child)) child.remove();
  }
  document.head.prepend(...nextHead.childNodes);
  for (const { link, media } of styles) {
   if (media === null) link.removeAttribute('media');
   else link.media = media;
  }
  document.body.replaceWith(nextBody);
  for (const code of [payload.data, payload.app]) {
   const script = document.createElement('script');
   script.textContent = code;
   document.body.append(script);
   script.remove();
  }
  document.querySelector('#team-lock').addEventListener('click', () => location.reload());
 }

 form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!window.isSecureContext || !window.crypto?.subtle) {
   status.textContent = '请通过发布后的 HTTPS 网址打开。';
   return;
  }
  const password = passwordInput.value.trim();
  button.disabled = true;
  status.textContent = '';
  try {
   const response = await fetch('site.enc.json', { cache: 'no-store' });
   if (!response.ok) throw new Error('Bundle unavailable');
   let payload;
   try {
    payload = await decrypt(await response.json(), password);
   } catch {
    status.textContent = '密码不正确，请重试。';
    passwordInput.select();
    return;
   }
   passwordInput.value = '';
   status.textContent = '正在打开网站…';
   await loadLeaflet();
   await mount(payload);
  } catch {
   status.textContent = '网站暂时无法载入，请刷新后重试。';
  } finally {
   button.disabled = false;
  }
 });
})();
