// Basic JavaScript for the cybersecurity toolkit

// Function to handle form submissions (example for port scanner)
function handlePortScan(event) {
    event.preventDefault();
    const ipAddress = document.getElementById('ip-address').value;
    const portRange = document.getElementById('port-range').value;

    // Send data to backend using AJAX
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/port-scan');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function() {
        if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText);
            // Update UI with results
            updatePortScanResults(response);
        } else {
            // Handle errors
            console.error('Error:', xhr.statusText);
        }
    };
    xhr.onerror = function() {
        console.error('Request failed');
    };
    xhr.send(JSON.stringify({ ipAddress, portRange }));
}

// Function to update UI with port scan results
function updatePortScanResults(results) {
    // Update the UI with the results (e.g., table, list, etc.)
    console.log('Port Scan Results:', results);
}

// Add event listeners to forms
document.addEventListener('DOMContentLoaded', function() {
    const portScannerForm = document.querySelector('#port-scanner form');
    if (portScannerForm) {
        portScannerForm.addEventListener('submit', handlePortScan);
    }
});
