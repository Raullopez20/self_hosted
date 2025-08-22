// Aplicación JavaScript principal - Password Manager Professional
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Inicializar modo oscuro
    initializeDarkMode();
    
    // Inicializar menú móvil
    initializeMobileMenu();
    
    // Inicializar tooltips y animaciones
    initializeAnimations();
    
    // Inicializar auto-hide para flash messages
    initializeFlashMessages();
    
    // Inicializar funcionalidades de contraseñas
    initializePasswordFeatures();
}

// === MODO OSCURO ===
function initializeDarkMode() {
    const darkModeToggle = document.getElementById('darkModeToggle');
    const html = document.documentElement;
    
    // Cargar preferencia guardada o detectar preferencia del sistema
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    // Aplicar tema: preferencia guardada > preferencia del sistema > claro por defecto
    if (savedTheme === 'dark' || (!savedTheme && systemPrefersDark)) {
        html.classList.add('dark');
    } else {
        html.classList.remove('dark');
    }
    
    // Toggle de modo oscuro
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            html.classList.toggle('dark');
            const isDark = html.classList.contains('dark');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
            
            // Animación del icono
            const icon = this.querySelector('i');
            icon.style.transform = 'rotate(180deg)';
            setTimeout(() => {
                icon.style.transform = 'rotate(0deg)';
            }, 300);
        });
    }

    // Escuchar cambios en la preferencia del sistema
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
        // Solo aplicar cambio automático si no hay preferencia guardada
        if (!localStorage.getItem('theme')) {
            if (e.matches) {
                html.classList.add('dark');
            } else {
                html.classList.remove('dark');
            }
        }
    });
}

// === MENÚ MÓVIL ===
function initializeMobileMenu() {
    const mobileMenuButton = document.getElementById('mobileMenuButton');
    const mobileMenu = document.getElementById('mobileMenu');
    
    if (mobileMenuButton && mobileMenu) {
        mobileMenuButton.addEventListener('click', function() {
            const isHidden = mobileMenu.classList.contains('hidden');
            
            if (isHidden) {
                mobileMenu.classList.remove('hidden');
                mobileMenu.style.maxHeight = '0px';
                mobileMenu.style.opacity = '0';
                
                // Animar apertura
                requestAnimationFrame(() => {
                    mobileMenu.style.transition = 'max-height 0.3s ease-out, opacity 0.3s ease-out';
                    mobileMenu.style.maxHeight = mobileMenu.scrollHeight + 'px';
                    mobileMenu.style.opacity = '1';
                });
                
                // Cambiar icono
                this.querySelector('i').classList.replace('fa-bars', 'fa-times');
            } else {
                // Animar cierre
                mobileMenu.style.maxHeight = '0px';
                mobileMenu.style.opacity = '0';
                
                setTimeout(() => {
                    mobileMenu.classList.add('hidden');
                }, 300);
                
                // Cambiar icono
                this.querySelector('i').classList.replace('fa-times', 'fa-bars');
            }
        });
    }
}

// === ANIMACIONES ===
function initializeAnimations() {
    // Intersection Observer para animaciones al hacer scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    // Observar elementos con clase animate-on-scroll
    document.querySelectorAll('.animate-on-scroll').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
        observer.observe(el);
    });
    
    // Animaciones de hover mejoradas para cards
    document.querySelectorAll('.card, .bg-white, .dark\\:bg-gray-800').forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px)';
            this.style.boxShadow = '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '';
        });
    });
}

// === FLASH MESSAGES ===
function initializeFlashMessages() {
    const flashContainer = document.getElementById('flashMessages');
    if (!flashContainer) return;
    
    // Auto-mostrar mensajes con animación
    const messages = flashContainer.querySelectorAll('.alert');
    messages.forEach((message, index) => {
        setTimeout(() => {
            message.style.transform = 'translateX(0)';
        }, index * 150);
        
        // Auto-ocultar después de 5 segundos
        setTimeout(() => {
            hideFlashMessage(message);
        }, 5000 + (index * 150));
    });
}

function hideFlashMessage(messageElement) {
    messageElement.style.transform = 'translateX(100%)';
    messageElement.style.opacity = '0';
    
    setTimeout(() => {
        messageElement.remove();
    }, 300);
}

// === FUNCIONALIDADES DE CONTRASEÑAS ===
function initializePasswordFeatures() {
    // Generador de contraseñas mejorado
    initializePasswordGenerator();
    
    // Copiado al portapapeles mejorado
    initializeClipboard();
    
    // Búsqueda en tiempo real
    initializeSearch();
    
    // Validación de formularios
    initializeFormValidation();
}

function initializePasswordGenerator() {
    const generateButtons = document.querySelectorAll('[data-action="generate-password"]');
    
    generateButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetInput = document.querySelector(this.dataset.target);
            if (!targetInput) return;
            
            // Mostrar loading
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Generando...';
            this.disabled = true;
            
            // Simular generación (en producción sería una llamada AJAX)
            setTimeout(() => {
                const password = generateSecurePassword();
                targetInput.value = password;
                
                // Trigger eventos para validación
                targetInput.dispatchEvent(new Event('input'));
                targetInput.dispatchEvent(new Event('change'));
                
                // Restaurar botón
                this.innerHTML = originalText;
                this.disabled = false;
                
                // Mostrar feedback
                showToast('Contraseña generada exitosamente', 'success');
            }, 500);
        });
    });
}

function generateSecurePassword(length = 16) {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const all = lowercase + uppercase + numbers + symbols;
    let password = '';
    
    // Asegurar al menos un carácter de cada tipo
    password += getRandomChar(lowercase);
    password += getRandomChar(uppercase);
    password += getRandomChar(numbers);
    password += getRandomChar(symbols);
    
    // Completar el resto
    for (let i = 4; i < length; i++) {
        password += getRandomChar(all);
    }
    
    // Mezclar
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

function getRandomChar(chars) {
    return chars[Math.floor(Math.random() * chars.length)];
}

function initializeClipboard() {
    document.addEventListener('click', function(e) {
        if (e.target.matches('[data-action="copy"]') || e.target.closest('[data-action="copy"]')) {
            e.preventDefault();
            
            const button = e.target.closest('[data-action="copy"]') || e.target;
            const text = button.dataset.text || button.textContent;
            
            copyToClipboard(text).then(() => {
                showCopyFeedback(button);
                showToast('Copiado al portapapeles', 'success');
            }).catch(() => {
                showToast('Error al copiar', 'error');
            });
        }
    });
}

async function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    } else {
        // Fallback para navegadores más antiguos
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        return new Promise((resolve, reject) => {
            if (document.execCommand('copy')) {
                resolve();
            } else {
                reject();
            }
            document.body.removeChild(textArea);
        });
    }
}

function showCopyFeedback(button) {
    const icon = button.querySelector('i');
    if (!icon) return;
    
    const originalClass = icon.className;
    icon.className = 'fas fa-check';
    
    setTimeout(() => {
        icon.className = originalClass;
    }, 2000);
}

function initializeSearch() {
    const searchInputs = document.querySelectorAll('input[type="search"], input[name="query"]');
    
    searchInputs.forEach(input => {
        let timeout;
        
        input.addEventListener('input', function() {
            clearTimeout(timeout);
            
            timeout = setTimeout(() => {
                const query = this.value.trim();
                if (query.length >= 2) {
                    performSearch(query);
                }
            }, 300);
        });
    });
}

function performSearch(query) {
    // En una implementación real, esto haría una búsqueda AJAX
    console.log('Buscando:', query);
}

function initializeFormValidation() {
    const forms = document.querySelectorAll('form[data-validate="true"]');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
                showToast('Por favor corrige los errores en el formulario', 'error');
            }
        });
        
        // Validación en tiempo real
        const inputs = form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('blur', () => validateField(input));
            input.addEventListener('input', () => clearFieldError(input));
        });
    });
}

function validateForm(form) {
    const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!validateField(input)) {
            isValid = false;
        }
    });
    
    return isValid;
}

function validateField(field) {
    const value = field.value.trim();
    let isValid = true;
    let message = '';
    
    // Validación requerido
    if (field.required && !value) {
        isValid = false;
        message = 'Este campo es requerido';
    }
    
    // Validación email
    if (field.type === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            isValid = false;
            message = 'Email inválido';
        }
    }
    
    // Validación contraseña
    if (field.type === 'password' && value) {
        if (value.length < 8) {
            isValid = false;
            message = 'La contraseña debe tener al menos 8 caracteres';
        }
    }
    
    // Mostrar/ocultar error
    if (isValid) {
        clearFieldError(field);
    } else {
        showFieldError(field, message);
    }
    
    return isValid;
}

function showFieldError(field, message) {
    clearFieldError(field);
    
    field.classList.add('border-red-500', 'focus:border-red-500', 'focus:ring-red-500');
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error mt-1 text-sm text-red-600 dark:text-red-400';
    errorDiv.innerHTML = `<i class="fas fa-exclamation-circle mr-1"></i>${message}`;
    
    field.parentNode.appendChild(errorDiv);
}

function clearFieldError(field) {
    field.classList.remove('border-red-500', 'focus:border-red-500', 'focus:ring-red-500');
    
    const errorDiv = field.parentNode.querySelector('.field-error');
    if (errorDiv) {
        errorDiv.remove();
    }
}

// === UTILIDADES ===
function showToast(message, type = 'info', duration = 3000) {
    const toast = createToastElement(message, type);
    document.body.appendChild(toast);
    
    // Animar entrada
    setTimeout(() => {
        toast.classList.add('show');
    }, 100);
    
    // Auto-ocultar
    setTimeout(() => {
        hideToast(toast);
    }, duration);
}

function createToastElement(message, type) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type} fixed top-4 right-4 max-w-sm z-50 transform translate-x-full opacity-0 transition-all duration-300`;
    
    const colors = {
        success: 'bg-green-500 text-white',
        error: 'bg-red-500 text-white',
        warning: 'bg-yellow-500 text-black',
        info: 'bg-blue-500 text-white'
    };
    
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-times-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    
    toast.innerHTML = `
        <div class="flex items-center p-4 rounded-lg shadow-lg ${colors[type]}">
            <i class="fas ${icons[type]} mr-3"></i>
            <span class="flex-1">${message}</span>
            <button onclick="hideToast(this.closest('.toast'))" class="ml-3 opacity-70 hover:opacity-100">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    return toast;
}

function hideToast(toast) {
    toast.classList.remove('show');
    toast.classList.add('translate-x-full', 'opacity-0');
    
    setTimeout(() => {
        toast.remove();
    }, 300);
}

// Agregar clase show para animación
const style = document.createElement('style');
style.textContent = `
    .toast.show {
        transform: translateX(0);
        opacity: 1;
    }
`;
document.head.appendChild(style);

// === EXPORTAR FUNCIONES GLOBALES ===
window.showToast = showToast;
window.copyToClipboard = copyToClipboard;
window.hideFlashMessage = hideFlashMessage;

// === MANEJO DE ERRORES ===
window.addEventListener('error', function(e) {
    console.error('Error capturado:', e.error);
    showToast('Ha ocurrido un error inesperado', 'error');
});

// === LOADING STATES ===
function showLoading(element) {
    const loadingHtml = `
        <div class="loading-overlay">
            <div class="loading-spinner"></div>
        </div>
    `;
    
    element.style.position = 'relative';
    element.insertAdjacentHTML('beforeend', loadingHtml);
}

function hideLoading(element) {
    const overlay = element.querySelector('.loading-overlay');
    if (overlay) {
        overlay.remove();
    }
}

window.showLoading = showLoading;
window.hideLoading = hideLoading;
