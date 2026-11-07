/**
 * CryptoGuard — Controlador de Interfaz y Flujo de Aplicación Estática
 */
(function () {
    'use strict';

    // Estado temporal en memoria de la operación activa en el laboratorio
    let currentOperationState = null;

    const sampleCredentials = [
        { username: 'operador.seguridad_01', password: 'ClaveSegura#2026$OAEP_WebCrypto!' },
        { username: 'analista.redes_02', password: 'RSA2048*AES256_GCM#Token99' },
        { username: 'auditor.sistemas_03', password: 'Prot3ccion_Cr1pt0gr4fica!2026' }
    ];
    let sampleIndex = 0;

    function maskString(str) {
        const len = Math.max(12, Array.from(String(str || '')).length);
        return '•'.repeat(len);
    }

    function escapeHtml(value) {
        const div = document.createElement('div');
        div.textContent = String(value ?? '');
        return div.innerHTML;
    }

    document.addEventListener('DOMContentLoaded', async function () {
        const Engine = window.CryptoGuardEngine;
        const History = window.CryptoGuardHistory;

        // Elementos de navegación
        const sidebar = document.getElementById('cgSidebar');
        const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
        const pageTitle = document.getElementById('pageTitle');
        const navButtons = document.querySelectorAll('[data-nav-target]');
        const sections = document.querySelectorAll('.cg-section');

        // Elementos de estado global
        const topbarStatusBadge = document.getElementById('topbarStatusBadge');
        const homeServiceBadge = document.getElementById('homeServiceBadge');
        const alertContainer = document.getElementById('alertContainer');

        // Elementos del formulario de laboratorio
        const encryptForm = document.getElementById('encryptForm');
        const usernameInput = document.getElementById('usernameInput');
        const passwordInput = document.getElementById('passwordInput');
        const passwordByteCounter = document.getElementById('passwordByteCounter');
        const togglePasswordInputBtn = document.getElementById('togglePasswordInputBtn');
        const togglePasswordInputIcon = document.getElementById('togglePasswordInputIcon');
        const loadSampleBtn = document.getElementById('loadSampleBtn');
        const resetLabBtn = document.getElementById('resetLabBtn');

        // Contenedores de resultados en laboratorio
        const encryptionResultsContainer = document.getElementById('encryptionResultsContainer');
        const aesOriginalBox = document.getElementById('aesOriginalBox');
        const aesAlgorithmBox = document.getElementById('aesAlgorithmBox');
        const aesCiphertextBox = document.getElementById('aesCiphertextBox');
        const aesIvBox = document.getElementById('aesIvBox');
        const aesTagBox = document.getElementById('aesTagBox');
        const aesDecryptedBox = document.getElementById('aesDecryptedBox');

        const rsaOriginalBox = document.getElementById('rsaOriginalBox');
        const toggleRsaOriginalBtn = document.getElementById('toggleRsaOriginalBtn');
        const rsaAlgorithmBox = document.getElementById('rsaAlgorithmBox');
        const rsaKeySizeBox = document.getElementById('rsaKeySizeBox');
        const rsaCiphertextBox = document.getElementById('rsaCiphertextBox');
        const rsaDecryptedBox = document.getElementById('rsaDecryptedBox');
        const toggleRsaDecryptedBtn = document.getElementById('toggleRsaDecryptedBtn');

        const decryptVerifyBtn = document.getElementById('decryptVerifyBtn');
        const verificationBanner = document.getElementById('verificationBanner');

        // Elementos de tablas de historial
        const homeRecentBody = document.getElementById('homeRecentBody');
        const homeTotalCount = document.getElementById('homeTotalCount');
        const historyTableBody = document.getElementById('historyTableBody');
        const historyTotalCount = document.getElementById('historyTotalCount');
        const filterOperationType = document.getElementById('filterOperationType');
        const filterAlgorithm = document.getElementById('filterAlgorithm');
        const filterStatus = document.getElementById('filterStatus');
        const clearFiltersBtn = document.getElementById('clearFiltersBtn');

        // 1. Navegación entre las 3 vistas (Inicio, Laboratorio, Historial)
        const sectionTitles = {
            'section-inicio': 'Inicio',
            'section-laboratorio': 'Laboratorio Criptográfico',
            'section-historial': 'Historial de Operaciones'
        };

        function navigateToSection(sectionId) {
            sections.forEach((sec) => {
                sec.classList.toggle('active', sec.id === sectionId);
            });
            navButtons.forEach((btn) => {
                const target = btn.getAttribute('data-nav-target');
                if ( btn.classList.contains('cg-nav-link') ) {
                    btn.classList.toggle('active', target === sectionId);
                }
            });
            if (pageTitle && sectionTitles[sectionId]) {
                pageTitle.textContent = sectionTitles[sectionId];
            }
            if (sidebar) {
                sidebar.classList.remove('show');
            }
            hideAlert();
            renderHistoryTables();
        }

        navButtons.forEach((btn) => {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                const target = btn.getAttribute('data-nav-target');
                if (target) {
                    navigateToSection(target);
                }
            });
        });

        if (sidebarToggleBtn && sidebar) {
            sidebarToggleBtn.addEventListener('click', function () {
                sidebar.classList.toggle('show');
            });
        }

        // 2. Mensajes de alerta claros
        function showAlert(message, type = 'danger') {
            if (!alertContainer) return;
            const isDanger = type === 'danger';
            const borderColor = isDanger ? 'var(--cg-danger)' : 'var(--cg-success)';
            const bgColor = isDanger ? 'rgba(239, 68, 68, 0.14)' : 'rgba(34, 197, 94, 0.14)';
            const textColor = isDanger ? '#FCA5A5' : '#86EFAC';
            const icon = isDanger ? 'bi-exclamation-octagon-fill text-danger' : 'bi-check-circle-fill text-success';

            alertContainer.innerHTML = `
                <div class="alert border-0 mb-4 d-flex align-items-center justify-content-between" style="background-color: ${bgColor}; color: ${textColor}; border-left: 4px solid ${borderColor} !important;">
                    <div class="d-flex align-items-center gap-2">
                        <i class="bi ${icon}"></i>
                        <span>${escapeHtml(message)}</span>
                    </div>
                    <button type="button" class="btn-close btn-close-white btn-sm" aria-label="Cerrar" id="closeAlertBtn"></button>
                </div>
            `;
            const closeBtn = document.getElementById('closeAlertBtn');
            if (closeBtn) {
                closeBtn.addEventListener('click', hideAlert);
            }
        }

        function hideAlert() {
            if (alertContainer) {
                alertContainer.innerHTML = '';
            }
        }

        // 3. Inicialización automática de claves en memoria al abrir la sesión
        try {
            await Engine.initSessionKeys();
            if (topbarStatusBadge) {
                topbarStatusBadge.className = 'cg-badge-success d-none d-sm-inline-flex';
                topbarStatusBadge.innerHTML = '<i class="bi bi-check-circle-fill"></i><span>AES-256-GCM · RSA-2048</span>';
            }
            if (homeServiceBadge) {
                homeServiceBadge.className = 'cg-badge-success';
                homeServiceBadge.innerHTML = '<i class="bi bi-check-circle-fill"></i> Activo';
            }
        } catch (err) {
            if (topbarStatusBadge) {
                topbarStatusBadge.className = 'cg-badge-danger d-none d-sm-inline-flex';
                topbarStatusBadge.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i><span>Web Crypto Inactivo</span>';
            }
            if (homeServiceBadge) {
                homeServiceBadge.className = 'cg-badge-danger';
                homeServiceBadge.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> Inactivo';
            }
            showAlert(err.message || 'No fue posible inicializar Web Crypto API en este navegador.');
        }

        // 4. Contador de bytes UTF-8 para RSA-2048 OAEP-SHA256 (máx. 190 bytes)
        function updateByteCounter() {
            if (!passwordInput || !passwordByteCounter) return;
            const bytes = Engine.getUtf8ByteLength(passwordInput.value);
            passwordByteCounter.textContent = `${bytes} / 190 bytes UTF-8`;
            if (bytes > 190) {
                passwordByteCounter.classList.add('text-danger', 'fw-bold');
            } else {
                passwordByteCounter.classList.remove('text-danger', 'fw-bold');
            }
        }

        if (passwordInput) {
            passwordInput.addEventListener('input', updateByteCounter);
            updateByteCounter();
        }

        // Mostrar / ocultar contraseña en el input del formulario
        if (togglePasswordInputBtn && passwordInput) {
            togglePasswordInputBtn.addEventListener('click', function () {
                const isPass = passwordInput.getAttribute('type') === 'password';
                passwordInput.setAttribute('type', isPass ? 'text' : 'password');
                if (togglePasswordInputIcon) {
                    togglePasswordInputIcon.className = isPass ? 'bi bi-eye-slash' : 'bi bi-eye';
                }
            });
        }

        // Cargar datos de prueba
        if (loadSampleBtn && usernameInput && passwordInput) {
            loadSampleBtn.addEventListener('click', function () {
                const sample = sampleCredentials[sampleIndex % sampleCredentials.length];
                sampleIndex++;
                usernameInput.value = sample.username;
                passwordInput.value = sample.password;
                updateByteCounter();
                hideAlert();
            });
        }

        // Limpiar datos sensibles e iniciar una nueva operación
        function clearSensitiveOperationData() {
            currentOperationState = null;
            if (encryptionResultsContainer) {
                encryptionResultsContainer.classList.add('d-none');
            }
            if (verificationBanner) {
                verificationBanner.classList.add('d-none');
                verificationBanner.innerHTML = '';
            }
            if (aesOriginalBox) {
                aesOriginalBox.textContent = '';
                aesOriginalBox.setAttribute('data-raw-value', '');
            }
            if (aesCiphertextBox) {
                aesCiphertextBox.textContent = '';
                aesCiphertextBox.setAttribute('data-raw-value', '');
            }
            if (aesIvBox) {
                aesIvBox.textContent = '';
                aesIvBox.setAttribute('data-raw-value', '');
            }
            if (aesTagBox) {
                aesTagBox.textContent = '';
                aesTagBox.setAttribute('data-raw-value', '');
            }
            if (aesDecryptedBox) {
                aesDecryptedBox.textContent = 'Pendiente de descifrar';
                aesDecryptedBox.style.color = 'var(--cg-text-muted)';
            }
            if (rsaOriginalBox) {
                rsaOriginalBox.textContent = '';
                rsaOriginalBox.setAttribute('data-raw-value', '');
                rsaOriginalBox.setAttribute('data-masked-value', '');
                rsaOriginalBox.setAttribute('data-is-masked', 'true');
            }
            if (rsaCiphertextBox) {
                rsaCiphertextBox.textContent = '';
                rsaCiphertextBox.setAttribute('data-raw-value', '');
            }
            if (rsaDecryptedBox) {
                rsaDecryptedBox.textContent = 'Pendiente de descifrar';
                rsaDecryptedBox.setAttribute('data-raw-value', '');
                rsaDecryptedBox.setAttribute('data-masked-value', '');
                rsaDecryptedBox.setAttribute('data-is-masked', 'false');
                rsaDecryptedBox.style.color = 'var(--cg-text-muted)';
            }
            if (toggleRsaDecryptedBtn) {
                toggleRsaDecryptedBtn.classList.add('d-none');
            }
        }

        if (resetLabBtn) {
            resetLabBtn.addEventListener('click', function () {
                clearSensitiveOperationData();
                if (usernameInput) usernameInput.value = '';
                if (passwordInput) {
                    passwordInput.value = '';
                    passwordInput.setAttribute('type', 'password');
                }
                if (togglePasswordInputIcon) {
                    togglePasswordInputIcon.className = 'bi bi-eye';
                }
                updateByteCounter();
                hideAlert();
            });
        }

        // 5. Ejecutar Cifrado de Credenciales (AES-256-GCM y RSA-2048 OAEP-SHA256)
        if (encryptForm) {
            encryptForm.addEventListener('submit', async function (e) {
                e.preventDefault();
                hideAlert();
                clearSensitiveOperationData();

                const username = usernameInput ? usernameInput.value.trim() : '';
                const password = passwordInput ? passwordInput.value : '';

                if (!username && !password) {
                    showAlert('Los campos Usuario y Contraseña son obligatorios.');
                    return;
                }
                if (!username) {
                    showAlert('El campo Usuario es obligatorio.');
                    return;
                }
                if (!password) {
                    showAlert('El campo Contraseña es obligatorio.');
                    return;
                }

                const passBytes = Engine.getUtf8ByteLength(password);
                if (passBytes > 190) {
                    showAlert(`La contraseña supera los 190 bytes UTF-8 permitidos por RSA-2048 OAEP con SHA-256 (se ingresaron ${passBytes} bytes).`);
                    return;
                }

                try {
                    if (!Engine.hasActiveSessionKeys()) {
                        await Engine.initSessionKeys();
                    }

                    // 1. Cifrado simétrico del usuario con AES-256-GCM
                    let aesResult;
                    try {
                        aesResult = await Engine.encryptUsernameAES(username);
                        History.addOperation({
                            operationType: 'ENCRYPT',
                            algorithm: aesResult.algorithm,
                            status: 'SUCCESS',
                            executionTimeMs: aesResult.executionTimeMs
                        });
                    } catch (aesErr) {
                        History.addOperation({
                            operationType: 'ENCRYPT',
                            algorithm: 'AES-256-GCM',
                            status: 'ERROR',
                            executionTimeMs: 0
                        });
                        throw aesErr;
                    }

                    // 2. Cifrado asimétrico de la contraseña con RSA-2048 OAEP-SHA256
                    let rsaResult;
                    try {
                        rsaResult = await Engine.encryptPasswordRSA(password);
                        History.addOperation({
                            operationType: 'ENCRYPT',
                            algorithm: rsaResult.algorithm,
                            status: 'SUCCESS',
                            executionTimeMs: rsaResult.executionTimeMs
                        });
                    } catch (rsaErr) {
                        History.addOperation({
                            operationType: 'ENCRYPT',
                            algorithm: 'RSA-2048 OAEP-SHA256',
                            status: 'ERROR',
                            executionTimeMs: 0
                        });
                        throw rsaErr;
                    }

                    // Guardar estado en memoria para la verificación inversa
                    currentOperationState = {
                        originalUsername: username,
                        originalPassword: password,
                        aes: aesResult,
                        rsa: rsaResult
                    };

                    // Poblar resultados AES-256-GCM
                    aesOriginalBox.textContent = username;
                    aesOriginalBox.setAttribute('data-raw-value', username);
                    aesAlgorithmBox.textContent = aesResult.algorithm;
                    aesCiphertextBox.textContent = aesResult.ciphertext;
                    aesCiphertextBox.setAttribute('data-raw-value', aesResult.ciphertext);
                    aesIvBox.textContent = aesResult.iv;
                    aesIvBox.setAttribute('data-raw-value', aesResult.iv);
                    aesTagBox.textContent = aesResult.tag;
                    aesTagBox.setAttribute('data-raw-value', aesResult.tag);
                    aesDecryptedBox.textContent = 'Pendiente de descifrar';
                    aesDecryptedBox.style.color = 'var(--cg-text-muted)';

                    // Poblar resultados RSA-2048 OAEP-SHA256 (contraseña inicialmente oculta)
                    const maskedPass = maskString(password);
                    rsaOriginalBox.textContent = maskedPass;
                    rsaOriginalBox.setAttribute('data-raw-value', password);
                    rsaOriginalBox.setAttribute('data-masked-value', maskedPass);
                    rsaOriginalBox.setAttribute('data-is-masked', 'true');
                    if (toggleRsaOriginalBtn) {
                        toggleRsaOriginalBtn.innerHTML = '<i class="bi bi-eye"></i> Mostrar';
                    }

                    rsaAlgorithmBox.textContent = rsaResult.algorithm;
                    rsaKeySizeBox.textContent = `${rsaResult.keySizeBits} bits`;
                    rsaCiphertextBox.textContent = rsaResult.ciphertext;
                    rsaCiphertextBox.setAttribute('data-raw-value', rsaResult.ciphertext);
                    rsaDecryptedBox.textContent = 'Pendiente de descifrar';
                    rsaDecryptedBox.style.color = 'var(--cg-text-muted)';

                    encryptionResultsContainer.classList.remove('d-none');
                    renderHistoryTables();
                } catch (err) {
                    showAlert(err.message || 'Ocurrió un error al proteger las credenciales.');
                    renderHistoryTables();
                }
            });
        }

        // 6. Ejecutar Descifrado y Verificación
        if (decryptVerifyBtn) {
            decryptVerifyBtn.addEventListener('click', async function () {
                hideAlert();

                if (!Engine.hasActiveSessionKeys() || !currentOperationState) {
                    showAlert('Las claves de la sesión o los datos de la operación no están disponibles. Ejecute una nueva operación de cifrado.');
                    return;
                }

                let aesDecrypted = null;
                let aesError = null;
                let rsaDecrypted = null;
                let rsaError = null;

                // Descifrar AES-256-GCM
                try {
                    const aesDec = await Engine.decryptUsernameAES(
                        currentOperationState.aes.ciphertext,
                        currentOperationState.aes.iv,
                        currentOperationState.aes.tag
                    );
                    aesDecrypted = aesDec.plaintext;
                    History.addOperation({
                        operationType: 'DECRYPT',
                        algorithm: aesDec.algorithm,
                        status: 'SUCCESS',
                        executionTimeMs: aesDec.executionTimeMs
                    });
                } catch (err) {
                    aesError = err.message;
                    History.addOperation({
                        operationType: 'DECRYPT',
                        algorithm: 'AES-256-GCM',
                        status: 'ERROR',
                        executionTimeMs: 0
                    });
                }

                // Descifrar RSA-2048 OAEP-SHA256
                try {
                    const rsaDec = await Engine.decryptPasswordRSA(
                        currentOperationState.rsa.ciphertext
                    );
                    rsaDecrypted = rsaDec.plaintext;
                    History.addOperation({
                        operationType: 'DECRYPT',
                        algorithm: rsaDec.algorithm,
                        status: 'SUCCESS',
                        executionTimeMs: rsaDec.executionTimeMs
                    });
                } catch (err) {
                    rsaError = err.message;
                    History.addOperation({
                        operationType: 'DECRYPT',
                        algorithm: 'RSA-2048 OAEP-SHA256',
                        status: 'ERROR',
                        executionTimeMs: 0
                    });
                }

                // Actualizar bloque de resultado descifrado AES
                if (aesError === null && aesDecrypted !== null) {
                    aesDecryptedBox.textContent = aesDecrypted;
                    aesDecryptedBox.style.color = '#86EFAC';
                } else {
                    aesDecryptedBox.textContent = aesError || 'Error al descifrar usuario';
                    aesDecryptedBox.style.color = '#FCA5A5';
                }

                // Actualizar bloque de resultado descifrado RSA
                if (rsaError === null && rsaDecrypted !== null) {
                    const maskedRec = maskString(rsaDecrypted);
                    rsaDecryptedBox.textContent = rsaDecrypted;
                    rsaDecryptedBox.setAttribute('data-raw-value', rsaDecrypted);
                    rsaDecryptedBox.setAttribute('data-masked-value', maskedRec);
                    rsaDecryptedBox.setAttribute('data-is-masked', 'false');
                    rsaDecryptedBox.style.color = '#86EFAC';
                    if (toggleRsaDecryptedBtn) {
                        toggleRsaDecryptedBtn.classList.remove('d-none');
                        toggleRsaDecryptedBtn.innerHTML = '<i class="bi bi-eye-slash"></i> Ocultar';
                    }
                } else {
                    rsaDecryptedBox.textContent = rsaError || 'Error al descifrar contraseña';
                    rsaDecryptedBox.style.color = '#FCA5A5';
                    if (toggleRsaDecryptedBtn) {
                        toggleRsaDecryptedBtn.classList.add('d-none');
                    }
                }

                // Comprobar coincidencia exacta con los valores originales
                const userMatches = aesError === null && aesDecrypted === currentOperationState.originalUsername;
                const passMatches = rsaError === null && rsaDecrypted === currentOperationState.originalPassword;

                verificationBanner.classList.remove('d-none');
                if (userMatches && passMatches) {
                    verificationBanner.innerHTML = `
                        <div class="cg-card" style="border-color: rgba(34, 197, 94, 0.45);">
                            <div class="cg-card-body d-flex flex-wrap align-items-center justify-content-between gap-3" style="background: rgba(34, 197, 94, 0.08);">
                                <div class="d-flex align-items-center gap-3">
                                    <i class="bi bi-patch-check-fill fs-3 text-success"></i>
                                    <div>
                                        <h4 class="h6 mb-1 fw-bold text-light">Verificación Exitosa: Coincidencia Exacta (100%)</h4>
                                        <p class="small mb-0" style="color: #86EFAC;">
                                            El usuario descifrado con AES-256-GCM y la contraseña descifrada con RSA-2048 OAEP-SHA256 coinciden exactamente con los valores originales ingresados.
                                        </p>
                                    </div>
                                </div>
                                <span class="cg-badge-success"><i class="bi bi-check-circle-fill"></i> Ambos valores verificados</span>
                            </div>
                        </div>
                    `;
                } else {
                    verificationBanner.innerHTML = `
                        <div class="cg-card" style="border-color: rgba(239, 68, 68, 0.45);">
                            <div class="cg-card-body d-flex flex-wrap align-items-center justify-content-between gap-3" style="background: rgba(239, 68, 68, 0.1);">
                                <div class="d-flex align-items-center gap-3">
                                    <i class="bi bi-x-octagon-fill fs-3 text-danger"></i>
                                    <div>
                                        <h4 class="h6 mb-1 fw-bold text-light">Error en Descifrado o Verificación</h4>
                                        <p class="small mb-0" style="color: #FCA5A5;">
                                            ${escapeHtml(aesError || rsaError || 'Los valores recuperados no coinciden con las credenciales originales.')}
                                        </p>
                                    </div>
                                </div>
                                <span class="cg-badge-danger"><i class="bi bi-exclamation-triangle-fill"></i> Fallo de Verificación</span>
                            </div>
                        </div>
                    `;
                }

                renderHistoryTables();
            });
        }

        // 7. Botones de Copiar al Portapapeles y Mostrar/Ocultar Valores
        document.querySelectorAll('[data-copy-target]').forEach((button) => {
            button.addEventListener('click', function () {
                const targetId = button.getAttribute('data-copy-target');
                const targetEl = document.getElementById(targetId);
                if (!targetEl) return;

                const textToCopy = (targetEl.getAttribute('data-raw-value') || targetEl.textContent || '').trim();
                if (!textToCopy) return;

                navigator.clipboard.writeText(textToCopy).then(function () {
                    const prevHtml = button.innerHTML;
                    button.innerHTML = '<i class="bi bi-check2"></i> Copiado';
                    button.classList.add('text-success');
                    setTimeout(function () {
                        button.innerHTML = prevHtml;
                        button.classList.remove('text-success');
                    }, 1500);
                });
            });
        });

        document.querySelectorAll('[data-toggle-reveal]').forEach((button) => {
            button.addEventListener('click', function () {
                const targetId = button.getAttribute('data-toggle-reveal');
                const targetEl = document.getElementById(targetId);
                if (!targetEl) return;

                const isMasked = targetEl.getAttribute('data-is-masked') === 'true';
                const rawVal = targetEl.getAttribute('data-raw-value') || '';
                const maskedVal = targetEl.getAttribute('data-masked-value') || '••••••••••••';

                if (isMasked) {
                    targetEl.textContent = rawVal;
                    targetEl.setAttribute('data-is-masked', 'false');
                    button.innerHTML = '<i class="bi bi-eye-slash"></i> Ocultar';
                } else {
                    targetEl.textContent = maskedVal;
                    targetEl.setAttribute('data-is-masked', 'true');
                    button.innerHTML = '<i class="bi bi-eye"></i> Mostrar';
                }
            });
        });

        // 8. Renderizado de tablas de Historial en Memoria
        function buildRowsHtml(items) {
            if (!items || items.length === 0) {
                return `
                    <tr>
                        <td colspan="6" class="text-center py-4" style="color: var(--cg-text-muted);">
                            Sin operaciones registradas en la sesión actual.
                        </td>
                    </tr>
                `;
            }

            return items.map((op) => {
                const opBadge = op.operationType === 'ENCRYPT'
                    ? '<span class="font-mono text-info">Cifrado (ENCRYPT)</span>'
                    : '<span class="font-mono text-light">Descifrado (DECRYPT)</span>';

                const statusBadge = op.status === 'SUCCESS'
                    ? '<span class="cg-badge-success"><i class="bi bi-check-circle-fill"></i> Correcto</span>'
                    : '<span class="cg-badge-danger"><i class="bi bi-x-circle-fill"></i> Error</span>';

                return `
                    <tr>
                        <td class="font-mono text-muted">#${op.id}</td>
                        <td>${opBadge}</td>
                        <td class="font-mono text-light">${escapeHtml(op.algorithm)}</td>
                        <td>${statusBadge}</td>
                        <td class="font-mono text-info">${escapeHtml(op.executionTimeMs)} ms</td>
                        <td class="small font-mono" style="color: var(--cg-text-muted);">${escapeHtml(op.timestamp)}</td>
                    </tr>
                `;
            }).join('');
        }

        function renderHistoryTables() {
            const total = History.getTotalCount();
            if (homeTotalCount) homeTotalCount.textContent = String(total);
            if (historyTotalCount) historyTotalCount.textContent = String(total);

            if (homeRecentBody) {
                homeRecentBody.innerHTML = buildRowsHtml(History.getRecentOperations(8));
            }

            if (historyTableBody) {
                const filtered = History.getOperations({
                    operationType: filterOperationType ? filterOperationType.value : '',
                    algorithm: filterAlgorithm ? filterAlgorithm.value : '',
                    status: filterStatus ? filterStatus.value : ''
                });
                historyTableBody.innerHTML = buildRowsHtml(filtered);
            }
        }

        [filterOperationType, filterAlgorithm, filterStatus].forEach((selectEl) => {
            if (selectEl) {
                selectEl.addEventListener('change', renderHistoryTables);
            }
        });

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', function () {
                if (filterOperationType) filterOperationType.value = '';
                if (filterAlgorithm) filterAlgorithm.value = '';
                if (filterStatus) filterStatus.value = '';
                renderHistoryTables();
            });
        }

        renderHistoryTables();
    });
})();

