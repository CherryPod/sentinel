(function () {
    'use strict';

    // If already authenticated, redirect to main UI
    if (localStorage.getItem('sentinel-token')) {
        window.location.href = '/';
        return;
    }

    var form = document.getElementById('login-form');
    var usernameInput = document.getElementById('username');
    var pinInput = document.getElementById('pin');
    var loginBtn = document.getElementById('login-btn');
    var errorEl = document.getElementById('login-error');

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        errorEl.textContent = '';

        var username = usernameInput.value.trim();
        var pin = pinInput.value.trim();

        if (!username) {
            errorEl.textContent = 'Username is required';
            usernameInput.focus();
            return;
        }
        if (!pin) {
            errorEl.textContent = 'PIN is required';
            pinInput.focus();
            return;
        }

        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in...';

        fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, pin: pin }),
        }).then(function (resp) {
            if (resp.ok) return resp.json();
            return resp.json().then(function (body) {
                throw new Error(body.detail || 'Invalid credentials');
            });
        }).then(function (data) {
            if (data && data.token) {
                localStorage.setItem('sentinel-token', data.token);
                localStorage.setItem('sentinel-user-id', data.user_id || '');
                localStorage.setItem('sentinel-role', data.role || '');
                localStorage.setItem('sentinel-display-name', data.display_name || '');
                window.location.href = '/';
            } else {
                throw new Error('No token in response');
            }
        }).catch(function (err) {
            var msg = err.message || 'Login failed';
            errorEl.textContent = msg;
            console.error('Login error:', msg, err);
            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign in';
        });
    });

    usernameInput.focus();
})();
