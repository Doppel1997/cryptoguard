/**
 * CryptoGuard — Motor Criptográfico Web (Web Crypto API)
 * Implementa AES-256-GCM y RSA-2048 OAEP-SHA256 exclusivamente en memoria de sesión.
 */
(function (root) {
    'use strict';

    const AES_CONFIG = {
        name: 'AES-GCM',
        displayName: 'AES-256-GCM',
        keyLengthBits: 256,
        ivByteLength: 12,       // 96 bits
        tagBitLength: 128,      // 128 bits
        tagByteLength: 16       // 16 bytes
    };

    const RSA_CONFIG = {
        name: 'RSA-OAEP',
        displayName: 'RSA-2048 OAEP-SHA256',
        modulusLengthBits: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: 'SHA-256',
        maxPlaintextBytes: 190, // 256 - 2 * 32 - 2 = 190 bytes UTF-8
        cipherByteLength: 256
    };

    // Claves mantenidas exclusivamente en memoria privada de la sesión actual
    let sessionAesKey = null;
    let sessionRsaKeyPair = null;
    let initializationPromise = null;

    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder('utf-8', { fatal: true });

    /**
     * Obtiene la instancia nativa de Web Crypto API disponible en el entorno.
     */
    function getCryptoInstance() {
        const cryptoObj = (typeof window !== 'undefined' && window.crypto)
            ? window.crypto
            : (typeof globalThis !== 'undefined' && globalThis.crypto ? globalThis.crypto : null);

        if (!cryptoObj || !cryptoObj.subtle) {
            throw new Error(
                'Web Crypto API no está disponible. Abra la aplicación mediante HTTPS o localhost.'
            );
        }

        return cryptoObj;
    }

    /**
     * Convierte un Uint8Array o ArrayBuffer a cadena Base64.
     */
    function bytesToBase64(buffer) {
        const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
        if (typeof btoa === 'function') {
            let binary = '';
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
        return Buffer.from(bytes).toString('base64');
    }

    /**
     * Convierte una cadena Base64 a Uint8Array validando su formato.
     */
    function base64ToBytes(base64String) {
        if (typeof base64String !== 'string' || base64String.trim() === '') {
            throw new Error('El contenido Base64 proporcionado está vacío.');
        }

        const clean = base64String.trim();
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean) || clean.length % 4 !== 0) {
            throw new Error('El formato Base64 proporcionado es inválido.');
        }

        try {
            if (typeof atob === 'function') {
                const binary = atob(clean);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
                return bytes;
            }
            return new Uint8Array(Buffer.from(clean, 'base64'));
        } catch (_err) {
            throw new Error('No fue posible decodificar la cadena Base64.');
        }
    }

    /**
     * Calcula la longitud en bytes UTF-8 de una cadena.
     */
    function getUtf8ByteLength(text) {
        return textEncoder.encode(String(text ?? '')).byteLength;
    }

    /**
     * Inicializa automáticamente las claves de sesión en memoria (AES-256 y par RSA-2048).
     * Las claves se crean como no exportables (extractable: false) para máxima seguridad.
     */
    async function initSessionKeys(forceRegenerate = false) {
        if (!forceRegenerate && sessionAesKey && sessionRsaKeyPair) {
            return {
                ready: true,
                aesAlgorithm: AES_CONFIG.displayName,
                rsaAlgorithm: RSA_CONFIG.displayName
            };
        }

        if (!forceRegenerate && initializationPromise) {
            return initializationPromise;
        }

        initializationPromise = (async () => {
            const cryptoObj = getCryptoInstance();

            const [aesKey, rsaKeyPair] = await Promise.all([
                cryptoObj.subtle.generateKey(
                    {
                        name: AES_CONFIG.name,
                        length: AES_CONFIG.keyLengthBits
                    },
                    false,
                    ['encrypt', 'decrypt']
                ),
                cryptoObj.subtle.generateKey(
                    {
                        name: RSA_CONFIG.name,
                        modulusLength: RSA_CONFIG.modulusLengthBits,
                        publicExponent: RSA_CONFIG.publicExponent,
                        hash: RSA_CONFIG.hash
                    },
                    false,
                    ['encrypt', 'decrypt']
                )
            ]);

            sessionAesKey = aesKey;
            sessionRsaKeyPair = rsaKeyPair;
            initializationPromise = null;

            return {
                ready: true,
                aesAlgorithm: AES_CONFIG.displayName,
                rsaAlgorithm: RSA_CONFIG.displayName
            };
        })();

        return initializationPromise;
    }

    /**
     * Verifica si las claves de la sesión actual están activas en memoria.
     */
    function hasActiveSessionKeys() {
        return Boolean(
            sessionAesKey &&
            sessionRsaKeyPair &&
            sessionRsaKeyPair.publicKey &&
            sessionRsaKeyPair.privateKey
        );
    }

    /**
     * Obtiene metadatos de las claves activas sin exponer material secreto.
     */
    function getSessionKeyStatus() {
        if (!hasActiveSessionKeys()) {
            return {
                ready: false,
                aes: null,
                rsa: null
            };
        }

        return {
            ready: true,
            aes: {
                algorithm: sessionAesKey.algorithm.name,
                length: sessionAesKey.algorithm.length,
                extractable: sessionAesKey.extractable,
                usages: sessionAesKey.usages
            },
            rsa: {
                algorithm: sessionRsaKeyPair.publicKey.algorithm.name,
                modulusLength: sessionRsaKeyPair.publicKey.algorithm.modulusLength,
                hash: sessionRsaKeyPair.publicKey.algorithm.hash.name,
                publicExtractable: sessionRsaKeyPair.publicKey.extractable,
                privateExtractable: sessionRsaKeyPair.privateKey.extractable
            }
        };
    }

    /**
     * Cifra el nombre de usuario mediante AES-256-GCM con un IV aleatorio de 12 bytes por operación.
     */
    async function encryptUsernameAES(username) {
        const cleanUser = String(username ?? '');
        if (cleanUser.trim() === '') {
            throw new Error('El campo usuario es obligatorio para el cifrado AES-256-GCM.');
        }

        if (!hasActiveSessionKeys()) {
            await initSessionKeys();
        }

        const cryptoObj = getCryptoInstance();
        const iv = cryptoObj.getRandomValues(new Uint8Array(AES_CONFIG.ivByteLength));
        const plaintextBytes = textEncoder.encode(cleanUser);

        const startTime = performance.now();
        let encryptedBuffer;
        try {
            encryptedBuffer = await cryptoObj.subtle.encrypt(
                {
                    name: AES_CONFIG.name,
                    iv: iv,
                    tagLength: AES_CONFIG.tagBitLength
                },
                sessionAesKey,
                plaintextBytes
            );
        } catch (_err) {
            throw new Error('Error al ejecutar el cifrado simétrico AES-256-GCM.');
        }
        const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

        const fullBytes = new Uint8Array(encryptedBuffer);
        if (fullBytes.byteLength <= AES_CONFIG.tagByteLength) {
            throw new Error('La salida de AES-256-GCM no contiene un Authentication Tag válido.');
        }

        // En Web Crypto API AES-GCM, los últimos 16 bytes (128 bits) corresponden al Authentication Tag
        const ciphertextBytes = fullBytes.slice(0, fullBytes.byteLength - AES_CONFIG.tagByteLength);
        const tagBytes = fullBytes.slice(fullBytes.byteLength - AES_CONFIG.tagByteLength);

        return {
            algorithm: AES_CONFIG.displayName,
            keySizeBits: AES_CONFIG.keyLengthBits,
            ciphertext: bytesToBase64(ciphertextBytes),
            iv: bytesToBase64(iv),
            tag: bytesToBase64(tagBytes),
            executionTimeMs: executionTimeMs
        };
    }

    /**
     * Descifra el criptograma AES-256-GCM verificando el IV de 12 bytes y el Authentication Tag de 128 bits.
     */
    async function decryptUsernameAES(ciphertextBase64, ivBase64, tagBase64) {
        if (!hasActiveSessionKeys()) {
            throw new Error(
                'Las claves de la sesión no están disponibles. Ejecute una nueva operación de cifrado.'
            );
        }

        const ciphertextBytes = base64ToBytes(ciphertextBase64);
        const ivBytes = base64ToBytes(ivBase64);
        const tagBytes = base64ToBytes(tagBase64);

        if (ivBytes.byteLength !== AES_CONFIG.ivByteLength) {
            throw new Error('El IV de AES-256-GCM debe tener exactamente 12 bytes.');
        }

        if (tagBytes.byteLength !== AES_CONFIG.tagByteLength) {
            throw new Error('El Authentication Tag de AES-256-GCM debe tener exactamente 16 bytes (128 bits).');
        }

        if (ciphertextBytes.byteLength === 0) {
            throw new Error('El texto cifrado AES-256-GCM no puede estar vacío.');
        }

        // Recombinar Ciphertext + Authentication Tag para Web Crypto API
        const combinedBytes = new Uint8Array(ciphertextBytes.byteLength + tagBytes.byteLength);
        combinedBytes.set(ciphertextBytes, 0);
        combinedBytes.set(tagBytes, ciphertextBytes.byteLength);

        const cryptoObj = getCryptoInstance();
        const startTime = performance.now();

        let decryptedBuffer;
        try {
            decryptedBuffer = await cryptoObj.subtle.decrypt(
                {
                    name: AES_CONFIG.name,
                    iv: ivBytes,
                    tagLength: AES_CONFIG.tagBitLength
                },
                sessionAesKey,
                combinedBytes
            );
        } catch (_err) {
            throw new Error(
                'Fallo de verificación en AES-256-GCM: el texto cifrado, el IV o el Authentication Tag fueron manipulados o no corresponden a la clave de sesión.'
            );
        }

        const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

        return {
            plaintext: textDecoder.decode(decryptedBuffer),
            algorithm: AES_CONFIG.displayName,
            executionTimeMs: executionTimeMs
        };
    }

    /**
     * Cifra la contraseña mediante la clave pública RSA-2048 OAEP-SHA256.
     * Valida que la entrada no supere los 190 bytes UTF-8.
     */
    async function encryptPasswordRSA(password) {
        const cleanPassword = String(password ?? '');
        if (cleanPassword === '') {
            throw new Error('El campo contraseña es obligatorio para el cifrado RSA-2048 OAEP-SHA256.');
        }

        const plaintextBytes = textEncoder.encode(cleanPassword);
        if (plaintextBytes.byteLength > RSA_CONFIG.maxPlaintextBytes) {
            throw new Error(
                `La contraseña supera el límite máximo permitido por RSA-2048 OAEP-SHA256: máximo ${RSA_CONFIG.maxPlaintextBytes} bytes UTF-8 (se ingresaron ${plaintextBytes.byteLength} bytes).`
            );
        }

        if (!hasActiveSessionKeys()) {
            await initSessionKeys();
        }

        const cryptoObj = getCryptoInstance();
        const startTime = performance.now();

        let encryptedBuffer;
        try {
            encryptedBuffer = await cryptoObj.subtle.encrypt(
                {
                    name: RSA_CONFIG.name
                },
                sessionRsaKeyPair.publicKey,
                plaintextBytes
            );
        } catch (_err) {
            throw new Error('Error al ejecutar el cifrado asimétrico RSA-2048 OAEP-SHA256.');
        }

        const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

        return {
            algorithm: RSA_CONFIG.displayName,
            keySizeBits: RSA_CONFIG.modulusLengthBits,
            ciphertext: bytesToBase64(encryptedBuffer),
            byteLength: plaintextBytes.byteLength,
            maxBytes: RSA_CONFIG.maxPlaintextBytes,
            executionTimeMs: executionTimeMs
        };
    }

    /**
     * Descifra el criptograma de contraseña utilizando la clave privada RSA-2048 OAEP-SHA256.
     */
    async function decryptPasswordRSA(ciphertextBase64) {
        if (!hasActiveSessionKeys()) {
            throw new Error(
                'Las claves de la sesión no están disponibles. Ejecute una nueva operación de cifrado.'
            );
        }

        const cipherBytes = base64ToBytes(ciphertextBase64);
        if (cipherBytes.byteLength !== RSA_CONFIG.cipherByteLength) {
            throw new Error(
                `El bloque cifrado RSA-2048 debe tener exactamente ${RSA_CONFIG.cipherByteLength} bytes.`
            );
        }

        const cryptoObj = getCryptoInstance();
        const startTime = performance.now();

        let decryptedBuffer;
        try {
            decryptedBuffer = await cryptoObj.subtle.decrypt(
                {
                    name: RSA_CONFIG.name
                },
                sessionRsaKeyPair.privateKey,
                cipherBytes
            );
        } catch (_err) {
            throw new Error(
                'Fallo al descifrar con RSA-2048 OAEP-SHA256: el texto cifrado fue alterado o no corresponde a la clave privada de la sesión.'
            );
        }

        const executionTimeMs = Number((performance.now() - startTime).toFixed(2));

        return {
            plaintext: textDecoder.decode(decryptedBuffer),
            algorithm: RSA_CONFIG.displayName,
            keySizeBits: RSA_CONFIG.modulusLengthBits,
            executionTimeMs: executionTimeMs
        };
    }

    const CryptoGuardEngine = {
        AES_CONFIG,
        RSA_CONFIG,
        initSessionKeys,
        hasActiveSessionKeys,
        getSessionKeyStatus,
        getUtf8ByteLength,
        encryptUsernameAES,
        decryptUsernameAES,
        encryptPasswordRSA,
        decryptPasswordRSA,
        bytesToBase64,
        base64ToBytes
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = CryptoGuardEngine;
    } else {
        root.CryptoGuardEngine = CryptoGuardEngine;
    }
})(typeof window !== 'undefined' ? window : globalThis);

