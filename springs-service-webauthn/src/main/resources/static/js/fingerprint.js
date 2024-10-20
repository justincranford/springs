function fingerprintVisitor() {
    FingerprintJS.load().then(fp => {
        fp.get().then(result => {
            const fingerprintData = {
                visitorId: result.visitorId,
                userAgent: navigator.userAgent,
                screenResolution: {
                    width: window.screen.width,
                    height: window.screen.height,
                },
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language || navigator.userLanguage,
                platform: navigator.platform,
                plugins: Array.from(navigator.plugins).map(plugin => plugin.name),
                hardwareConcurrency: navigator.hardwareConcurrency || null,
                cookieEnabled: navigator.cookieEnabled,
                touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
                webGLVendor: (() => {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (!gl) return null;
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    return debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : null;
                })(),
                components: result.components,
            };
            console.log('Fingerprint Data:', JSON.stringify(fingerprintData));
        });
    });
};
