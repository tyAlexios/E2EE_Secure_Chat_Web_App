const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 8000 });

wss.on('connection', function connection(ws) {
    console.log('A new client connected!');

    ws.on('message', function incoming(message) {
        const data = JSON.parse(message);
        console.log("Received: Public key sent to peer: " + data.receiver_id);
        // ws.send(message);
        // console.log("Responce to Client: " + message);
    });
});
