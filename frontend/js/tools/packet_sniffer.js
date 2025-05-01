class PacketSniffer {
    constructor() {
        this.form = document.getElementById('packet-sniffer-form');
        this.resultsDiv = document.getElementById('packet-results');
        this.packetList = this.resultsDiv.querySelector('.packet-list');
        this.statsDiv = this.resultsDiv.querySelector('.stats-container');
        this.socket = io(API_BASE_URL);
        this.packets = [];
        this.bindEvents();
        this.initializeSocket();
    }

    bindEvents() {
        this.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const button = this.form.querySelector('button');
            
            if (button.dataset.action === 'start') {
                await this.startCapture();
                button.textContent = 'Stop Capture';
                button.dataset.action = 'stop';
            } else {
                await this.stopCapture();
                button.textContent = 'Start Capture';
                button.dataset.action = 'start';
            }
        });
    }

    initializeSocket() {
        this.socket.on('packet_captured', (packet) => {
            this.packets.unshift(packet);
            if (this.packets.length > 100) {
                this.packets.pop();
            }
            this.updatePacketList();
            this.updateStats();
        });
    }

    async startCapture() {
        const interface = this.form.querySelector('#interface').value;
        const filter = this.form.querySelector('#filter').value;

        try {
            await apiRequest('/packet-capture/start', 'POST', {
                interface,
                filter
            });
            this.resultsDiv.classList.remove('hidden');
        } catch (error) {
            alert('Failed to start capture: ' + error.message);
        }
    }

    async stopCapture() {
        try {
            const response = await apiRequest('/packet-capture/stop', 'POST');
            this.displayFinalResults(response.data);
        } catch (error) {
            alert('Failed to stop capture: ' + error.message);
        }
    }

    updatePacketList() {
        const packetsHtml = this.packets.map(packet => `
            <div class="bg-gray-700 p-2 rounded mb-2">
                <div class="flex justify-between text-sm">
                    <span>${packet.protocol || 'Unknown'}</span>
                    <span>${packet.timestamp}</span>
                </div>
                <div class="text-xs text-gray-300 mt-1">
                    ${packet.src} → ${packet.dst}
                </div>
                <div class="text-xs text-gray-400 mt-1">
                    ${packet.summary}
                </div>
            </div>
        `).join('');

        this.packetList.innerHTML = packetsHtml;
    }

    updateStats() {
        const stats = this.calculateStats();
        const statsHtml = `
            <div class="grid grid-cols-2 gap-4">
                <div class="bg-blue-500 p-4 rounded-lg">
                    <h4 class="font-bold">Total Packets</h4>
                    <p class="text-2xl">${stats.total}</p>
                </div>
                <div class="bg-green-500 p-4 rounded-lg">
                    <h4 class="font-bold">Protocols</h4>
                    <ul class="text-sm">
                        ${Object.entries(stats.protocols).map(([proto, count]) => 
                            `<li>${proto}: ${count}</li>`
                        ).join('')}
                    </ul>
                </div>
            </div>
        `;
        this.statsDiv.innerHTML = statsHtml;
    }

    calculateStats() {
        const protocols = {};
        this.packets.forEach(packet => {
            const proto = packet.protocol || 'Unknown';
            protocols[proto] = (protocols[proto] || 0) + 1;
        });

        return {
            total: this.packets.length,
            protocols
        };
    }

    displayFinalResults(data) {
        this.packets = data.packets;
        this.updatePacketList();
        this.updateStats();
    }
}

export default PacketSniffer;
