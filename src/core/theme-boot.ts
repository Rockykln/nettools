// Applies the saved light/dark choice before first paint. Inline so it does not block on a request;
// the CSP allows exactly this script by its hash (checked in test/theme-boot.test.ts).
export const THEME_BOOT = "try{var t=localStorage.getItem('theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t}catch(e){}";
export const THEME_BOOT_HASH = "'sha256-wsmnxD6kqdZZ/V2wQ85d92sMux2lvh7NN1y5/Y5SS5c='";
