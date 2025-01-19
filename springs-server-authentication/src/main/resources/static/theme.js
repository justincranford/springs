function setTheme(theme) {
    const htmlElement = document.documentElement;

    if (theme === 'user') {
        const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)').matches;
        theme = prefersDarkScheme ? 'dark' : 'light';
    }

    htmlElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);
}

document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'user';
    setTheme(savedTheme);
});

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (localStorage.getItem('theme') === 'user') {
        setTheme('user');
    }
});
