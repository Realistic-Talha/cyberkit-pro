// API configuration
const API_BASE_URL = 'http://127.0.0.1:5000/api';

// Theme handling
const themeToggle = document.getElementById('theme-toggle');
const body = document.body;

themeToggle.addEventListener('click', () => {
    const currentTheme = body.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    body.setAttribute('data-theme', newTheme);
    themeToggle.textContent = newTheme === 'light' ? '🌙' : '☀️';
});

// Export the apiRequest function
export async function apiRequest(endpoint, method = 'GET', data = null) {
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
            body: data ? JSON.stringify(data) : null,
        });
        
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.message || 'API request failed');
        }
        return result;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// Health check
async function checkApiHealth() {
    try {
        await apiRequest('/health');
        console.log('API is healthy');
    } catch (error) {
        console.error('API health check failed:', error);
    }
}

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    checkApiHealth();
    
    // Each tool page will handle its own initialization
    // through type="module" scripts
});
