
    async function updateStatus() {
      try {
        const res = await fetch('/api/protocol-status');
        const status = await res.json();
        
        const container = document.getElementById('status-container');
        container.innerHTML = '';
        
        for (const [protocol, state] of Object.entries(status)) {
          const card = document.createElement('div');
          card.className = `status-card ${state.split(' ')[0]}`;
          card.innerHTML = `
            <h3>${protocol.toUpperCase()}</h3>
            <p>Status: ${state.toUpperCase()}</p>
            <p>Last checked: ${new Date().toLocaleTimeString()}</p>
          `;
          container.appendChild(card);
        }
      } catch (err) {
        console.error('Failed to update status:', err);
      }
    }
    
    updateStatus();
    setInterval(updateStatus, 5000);
  