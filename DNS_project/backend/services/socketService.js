/**
 * Socket Service - Real-time log streaming to frontend
 */

const { activeScanners } = require("./scanManager");

function socketHandler(io) {
  io.on("connection", (socket) => {
    console.log(`[SOCKET] Client connected: ${socket.id}`);

    // Subscribe to a scan's logs
    socket.on("subscribe", ({ scanId }) => {
      if (scanId) {
        socket.join(`scan:${scanId}`);
        console.log(`[SOCKET] ${socket.id} subscribed to scan:${scanId}`);

        // Send current status if scan exists
        const scanner = activeScanners.get(scanId);
        if (scanner) {
          socket.emit("scan:status", {
            scanId,
            status: scanner.status,
            domain: scanner.domain,
            progress: scanner.progress,
          });
        }
      }
    });

    socket.on("unsubscribe", ({ scanId }) => {
      socket.leave(`scan:${scanId}`);
    });

    socket.on("disconnect", () => {
      console.log(`[SOCKET] Client disconnected: ${socket.id}`);
    });
  });
}

/**
 * Emit a log line to all subscribers of a scan
 */
function emitLog(io, scanId, message) {
  io.to(`scan:${scanId}`).emit("scan:log", {
    scanId,
    message,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Emit a status update
 */
function emitStatus(io, scanId, status) {
  io.to(`scan:${scanId}`).emit("scan:status", {
    scanId,
    ...status,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Emit progress update
 */
function emitProgress(io, scanId, stage, percent) {
  io.to(`scan:${scanId}`).emit("scan:progress", {
    scanId,
    stage,
    percent,
    timestamp: new Date().toISOString(),
  });
}

module.exports = { socketHandler, emitLog, emitStatus, emitProgress };
