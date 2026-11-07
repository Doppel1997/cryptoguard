/**
 * CryptoGuard — Gestor de Historial de Operaciones en Memoria
 * Almacena únicamente metadatos de operaciones durante la sesión actual sin persistencia externa.
 */
(function (root) {
    'use strict';

    const operationsLog = [];
    let sequenceCounter = 1;

    function formatTimestamp(date) {
        const pad = (n) => String(n).padStart(2, '0');
        return (
            date.getFullYear() + '-' +
            pad(date.getMonth() + 1) + '-' +
            pad(date.getDate()) + ' ' +
            pad(date.getHours()) + ':' +
            pad(date.getMinutes()) + ':' +
            pad(date.getSeconds())
        );
    }

    /**
     * Registra una operación criptográfica en la memoria de la sesión actual.
     * Nunca almacena usuarios originales, contraseñas ni claves.
     */
    function addOperation({ operationType, algorithm, status, executionTimeMs = 0 }) {
        const entry = Object.freeze({
            id: sequenceCounter++,
            timestamp: formatTimestamp(new Date()),
            operationType: operationType === 'DECRYPT' ? 'DECRYPT' : 'ENCRYPT',
            algorithm: String(algorithm || ''),
            status: status === 'ERROR' ? 'ERROR' : 'SUCCESS',
            executionTimeMs: Number(executionTimeMs || 0).toFixed(2)
        });

        operationsLog.unshift(entry);
        return entry;
    }

    /**
     * Obtiene la lista de operaciones aplicando filtros opcionales.
     */
    function getOperations(filters = {}) {
        return operationsLog.filter((item) => {
            if (filters.operationType && item.operationType !== filters.operationType) {
                return false;
            }
            if (filters.algorithm && item.algorithm !== filters.algorithm) {
                return false;
            }
            if (filters.status && item.status !== filters.status) {
                return false;
            }
            return true;
        });
    }

    /**
     * Obtiene las últimas N operaciones registradas.
     */
    function getRecentOperations(limit = 8) {
        return operationsLog.slice(0, limit);
    }

    /**
     * Obtiene el conteo total de operaciones en la sesión.
     */
    function getTotalCount() {
        return operationsLog.length;
    }

    /**
     * Limpia el historial en memoria (útil para pruebas automatizadas).
     */
    function clearHistory() {
        operationsLog.length = 0;
        sequenceCounter = 1;
    }

    const CryptoGuardHistory = {
        addOperation,
        getOperations,
        getRecentOperations,
        getTotalCount,
        clearHistory
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = CryptoGuardHistory;
    } else {
        root.CryptoGuardHistory = CryptoGuardHistory;
    }
})(typeof window !== 'undefined' ? window : globalThis);

