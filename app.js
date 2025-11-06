// Application State Management
class BankingSupportApp {
    constructor() {
        this.currentUser = null;
        this.currentView = null;
        this.tickets = [];
        this.users = [];
        this.departments = [];
        this.knowledgeBase = [];
        this.routingRules = {};
        this.nextTicketId = 1002;
        this.nextUserId = 4;
        this.sessionId = null; // for backend chat session continuity
        this.chatSessions = new Map(); // Store chat sessions per user
        this.currentChatSession = null;
        this.nextSessionId = 1;
        this.googleClientId = null;
        this.googleEnabled = false;
        
        this.initializeData();
        this.bindEvents();
        this.initializeGoogleAuth();
        this.checkAuthState();
    }

    // Knowledge Base
    renderKnowledgeBase() {
        const container = document.getElementById('kb-results');
        this.displayKnowledgeBase(this.knowledgeBase, container);

        // Show "Add" button for admin/support
        const addBtn = document.getElementById('add-kb-btn');
        if (this.currentUser.role === 'admin' || this.currentUser.role === 'support_agent') {
            addBtn.classList.remove('hidden');
            addBtn.onclick = () => this.showKbModal();
        } else {
            addBtn.classList.add('hidden');
        }
    }

    searchKnowledgeBase(query) {
        const container = document.getElementById('kb-results');
        if (!query.trim()) {
            this.displayKnowledgeBase(this.knowledgeBase, container);
            return;
        }

        const results = this.knowledgeBase.filter(article =>
            article.title.toLowerCase().includes(query.toLowerCase()) ||
            article.solution.toLowerCase().includes(query.toLowerCase()) ||
            article.keywords.some(keyword => keyword.toLowerCase().includes(query.toLowerCase()))
        );

        this.displayKnowledgeBase(results, container);
    }

    displayKnowledgeBase(articles, container) {
        if (articles.length === 0) {
            container.innerHTML = '<p class="text-center">No articles found.</p>';
            return;
        }

        container.innerHTML = articles.map(article => `
            <div class="kb-article">
                <div class="kb-category">${this.escapeHtml(article.category)}</div>
                <h4>${this.escapeHtml(article.title)}</h4>
                <div class="kb-solution">${marked.parse(article.solution)}</div>
                ${(this.currentUser.role === 'admin' || this.currentUser.role === 'support_agent') ? `
                    <div class="kb-actions">
                        <button class="btn btn--sm btn--secondary" onclick="app.showKbModal(${article.id})">Edit</button>
                        <button class="btn btn--sm btn--danger" onclick="app.deleteKnowledge(${article.id})">Delete</button>
                    </div>
                ` : ""}
            </div>
        `).join('');
    }

    // Modal for add/edit KB
    showKbModal(articleId = null) {
        const modal = document.getElementById('kb-modal');
        const form = document.getElementById('kb-form');

        if (articleId) {
            const article = this.knowledgeBase.find(a => a.id === articleId);
            if (!article) return;
            document.getElementById('kb-id').value = article.id;
            document.getElementById('kb-title').value = article.title;
            document.getElementById('kb-category').value = article.category;
            document.getElementById('kb-solution').value = article.solution;
            document.getElementById('kb-keywords').value = article.keywords.join(', ');
            document.getElementById('kb-modal-title').textContent = "Edit Knowledge";
        } else {
            form.reset();
            document.getElementById('kb-id').value = '';
            document.getElementById('kb-modal-title').textContent = "Add Knowledge";
        }

        modal.classList.remove('hidden');

        // Cancel button
        document.getElementById('cancel-kb').onclick = () => this.closeModal('kb-modal');

        // Submit form
        form.onsubmit = (e) => {
            e.preventDefault();
            this.saveKnowledge();
        };
    }

    saveKnowledge() {
        const id = document.getElementById('kb-id').value;
        const title = document.getElementById('kb-title').value.trim();
        const category = document.getElementById('kb-category').value.trim();
        const solution = document.getElementById('kb-solution').value.trim();
        const keywords = document.getElementById('kb-keywords').value.trim().split(',').map(k => k.trim());

        if (!title || !category || !solution) {
            alert("All fields except keywords are required.");
            return;
        }

        if (id) {
            // Update existing
            const article = this.knowledgeBase.find(a => a.id == id);
            if (article) {
                article.title = title;
                article.category = category;
                article.solution = solution;
                article.keywords = keywords;
            }
        } else {
            // Add new
            const newArticle = {
                id: this.knowledgeBase.length ? Math.max(...this.knowledgeBase.map(a => a.id)) + 1 : 1,
                title, category, solution, keywords
            };
            this.knowledgeBase.push(newArticle);
        }

        this.closeModal('kb-modal');
        this.renderKnowledgeBase();
    }

    deleteKnowledge(id) {
        if (!confirm("Are you sure you want to delete this knowledge entry?")) return;
        this.knowledgeBase = this.knowledgeBase.filter(a => a.id !== id);
        this.renderKnowledgeBase();
    }


    async initializeGoogleAuth() {
        try {
            const response = await fetch('http://localhost:8000/auth/config');
            const config = await response.json();
            
            this.googleClientId = config.google_client_id;
            this.googleEnabled = config.google_enabled;
            
            if (this.googleEnabled) {
                // Update the Google Sign-In button with the client ID
                const googleOnload = document.getElementById('g_id_onload');
                if (googleOnload) {
                    googleOnload.setAttribute('data-client_id', this.googleClientId);
                }
                
                // Show Google sign-in container
                const googleContainer = document.getElementById('google-signin-container');
                if (googleContainer) {
                    googleContainer.style.display = 'block';
                }
            } else {
                // Hide Google sign-in if not configured
                const googleContainer = document.getElementById('google-signin-container');
                if (googleContainer) {
                    googleContainer.style.display = 'none';
                }
            }
        } catch (error) {
            console.error('Failed to initialize Google Auth:', error);
            this.googleEnabled = false;
        }
    }

    initializeData() {
        // Initialize with sample data
        this.users = [
            {
                id: 1,
                username: "john.doe",
                password: "password123",
                role: "end_user",
                name: "John Doe",
                department: "Branch Staff",
                email: "john.doe@bank.com",
                active: true
            },
            {
                id: 2,
                username: "supportdesk",
                password: "password123",
                role: "support_agent",
                name: "Support Agent",
                department: "IT",
                email: "it.support@bank.com",
                active: true
            },
            {
                id: 3,
                username: "admin",
                password: "admin123",
                role: "admin",
                name: "System Administrator",
                department: "Administration",
                email: "admin@bank.com",
                active: true
            }
        ];

        this.departments = [
            { id: 1, name: "IT", description: "Hardware, OS, Network, AD/Internet access" },
            { id: 2, name: "Digital Banking", description: "Digital Banking software issues" },
            { id: 3, name: "Operations", description: "Core banking access, teller-related issues" }
        ];
        this.knowledgeBase = [
            {
                id: 1,
                title: "Password Reset",
                category: "Authentication",
                solution: "To reset your password, contact your IT administrator or use the self-service portal at portal.bank.com",
                keywords: ["password", "reset", "login", "authentication"]
            },
            {
                id: 2,
                title: "Printer Not Working",
                category: "Hardware",
                solution: "1. Check if printer is powered on\n2. Verify cable connections\n3. Check if paper is loaded\n4. Restart the printer\n5. If issue persists, contact IT support",
                keywords: ["printer", "print", "hardware", "not working"]
            },
            {
                id: 3,
                title: "Digital Banking App Error",
                category: "Software",
                solution: "Clear browser cache, disable browser extensions, or try using a different browser. If error persists, contact Digital Banking team.",
                keywords: ["digital banking", "app", "error", "software"]
            },
            {
                id: 4,
                title: "Network Connection Issues",
                category: "Network",
                solution: "1. Check network cables\n2. Restart your computer\n3. Try connecting to a different network\n4. Contact IT if problem persists",
                keywords: ["network", "connection", "internet", "offline"]
            },
            {
                id: 5,
                title: "Core Banking System Access",
                category: "Software",
                solution: "If you cannot access the core banking system, verify your credentials and check with Operations team for system status.",
                keywords: ["core banking", "access", "login", "system"]
            }
        ];

        this.routingRules = {
            "hardware": "IT",
            "software": "IT",
            "network": "IT",
            "password": "IT",
            "authentication": "IT",
            "digital banking": "Digital Banking",
            "mobile app": "Digital Banking",
            "core banking": "Operations",
            "teller": "Operations",
            "compliance": "AML/CFT",
            "loan": "Loan"
        };

        this.tickets = [
            {
                id: 1001,
                title: "Cannot access digital banking portal",
                description: "Getting error message when trying to log into the digital banking system",
                category: "Software",
                priority: "High",
                status: "Open",
                createdBy: 1,
                assignedTo: null,
                department: "Digital Banking",
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                comments: []
            },
            {
                id: 1002,
                title: "Printer not working in branch office",
                description: "The printer in the main branch is not responding when trying to print customer documents.",
                category: "Hardware",
                priority: "Medium",
                status: "In Progress",
                createdBy: 1,
                assignedTo: 2,
                department: "IT",
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                comments: ['printer doesnt work properly']
            }
        ];
    }

    bindEvents() {
        // Login form
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        // Logout
        document.getElementById('logout-btn').addEventListener('click', () => {
            this.handleLogout();
        });

        // Chat interface
        document.getElementById('send-message').addEventListener('click', () => {
            this.sendChatMessage();
        });

        document.getElementById('chat-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendChatMessage();
            }
        });

        // Chat history management
        document.getElementById('new-chat-btn').addEventListener('click', () => {
            this.startNewChat();
        });

        // Modal events
        document.getElementById('close-modal').addEventListener('click', () => {
            this.closeModal('ticket-modal');
        });

        document.getElementById('close-create-modal').addEventListener('click', () => {
            this.closeModal('create-ticket-modal');
        });

        document.getElementById('cancel-create-ticket').addEventListener('click', () => {
            this.closeModal('create-ticket-modal');
        });

        document.getElementById('create-ticket-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.createTicket();
        });

        // User management
        document.getElementById('add-user-btn').addEventListener('click', () => {
            this.showAddUserModal();
        });

        document.getElementById('close-add-user-modal').addEventListener('click', () => {
            this.closeModal('add-user-modal');
        });

        document.getElementById('cancel-add-user').addEventListener('click', () => {
            this.closeModal('add-user-modal');
        });

        document.getElementById('add-user-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.addUser();
        });

        // Knowledge base search
        document.getElementById('kb-search').addEventListener('input', (e) => {
            this.searchKnowledgeBase(e.target.value);
        });

        // Filters
        document.getElementById('status-filter')?.addEventListener('change', () => {
            this.renderAgentTickets();
        });

        document.getElementById('priority-filter')?.addEventListener('change', () => {
            this.renderAgentTickets();
        });

        document.getElementById('admin-status-filter')?.addEventListener('change', () => {
            this.renderAllTickets();
        });

        document.getElementById('admin-department-filter')?.addEventListener('change', () => {
            this.renderAllTickets();
        });

        // Modal click outside to close
        document.addEventListener('click', (e) => {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (e.target === modal) {
                    modal.classList.add('hidden');
                }
            });
        });
    }

    async handleGoogleSignIn(response) {
        try {
            const authResponse = await fetch('http://localhost:8000/auth/google', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    credential: response.credential
                })
            });

            const data = await authResponse.json();
            
            if (authResponse.ok && data.success) {
                // Store the token
                localStorage.setItem('auth-token', data.token);
                
                // Set current user from Google data
                this.currentUser = {
                    id: data.user.id,
                    username: data.user.email,
                    name: data.user.name,
                    email: data.user.email,
                    role: data.user.role,
                    department: data.user.department,
                    picture: data.user.picture,
                    active: true
                };
                
                this.showMainApp();
                
                // Hide any login errors
                const errorEl = document.getElementById('login-error');
                if (errorEl) {
                    errorEl.classList.add('hidden');
                }
            } else {
                throw new Error(data.detail || 'Google authentication failed');
            }
        } catch (error) {
            console.error('Google Sign-In error:', error);
            const errorEl = document.getElementById('login-error');
            if (errorEl) {
                errorEl.textContent = 'Google Sign-In failed. Please try again.';
                errorEl.classList.remove('hidden');
            }
        }
    }

    checkAuthState() {
        const token = localStorage.getItem('auth-token');
        if (token) {
            try {
                // Simulate JWT decode
                const payload = JSON.parse(atob(token.split('.')[1]));
                
                if (payload.exp > Date.now() / 1000) {
                    // Create user object from token payload
                    this.currentUser = {
                        id: payload.user_id,
                        username: payload.email,
                        name: payload.name,
                        email: payload.email,
                        role: payload.role,
                        department: payload.department || 'General',
                        active: true
                    };
                    this.showMainApp();
                    return;
                }
            } catch (e) {
                // Invalid token
                console.error('Invalid token:', e);
            }
        }
        this.showLoginScreen();
    }

    handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorEl = document.getElementById('login-error');

        const user = this.users.find(u => u.username === username && u.password === password && u.active);
        
        if (user) {
            // Create JWT-like token
            const token = this.createToken(user);
            localStorage.setItem('auth-token', token);
            this.currentUser = user;
            this.showMainApp();
            errorEl.classList.add('hidden');
        } else {
            errorEl.textContent = 'Invalid username or password';
            errorEl.classList.remove('hidden');
        }
    }

    createToken(user) {
        const header = btoa(JSON.stringify({ typ: 'JWT', alg: 'HS256' }));
        const payload = btoa(JSON.stringify({
            userId: user.id,
            username: user.username,
            role: user.role,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
        }));
        return `${header}.${payload}.signature`;
    }

    handleLogout() {
        localStorage.removeItem('auth-token');
        this.currentUser = null;
        this.currentChatSession = null;
        this.sessionId = null;
        this.showLoginScreen();
    }

    showLoginScreen() {
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('main-app').classList.add('hidden');
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
    }

    showMainApp() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('main-app').classList.remove('hidden');
        this.setupUserInterface();
        this.loadUserChatSessions();
        this.showDefaultView();
    }

    setupUserInterface() {
        // Update user info
        const userInfoEl = document.getElementById('user-info');
        if (this.currentUser.picture) {
            userInfoEl.innerHTML = `
                <img src="${this.currentUser.picture}" alt="Profile" class="user-avatar">
                <span>${this.currentUser.name} (${this.formatRole(this.currentUser.role)})</span>
            `;
        } else {
            userInfoEl.textContent = `${this.currentUser.name} (${this.formatRole(this.currentUser.role)})`;
        }

        // Setup navigation based on role
        const navLinks = document.getElementById('nav-links');
        navLinks.innerHTML = '';

        const navigation = this.getNavigationForRole(this.currentUser.role);
        navigation.forEach(nav => {
            const link = document.createElement('a');
            link.href = '#';
            link.className = 'nav-link';
            link.textContent = nav.label;
            link.dataset.view = nav.view; // track target view for active state
            link.addEventListener('click', (e) => {
                e.preventDefault();
                this.showView(nav.view);
            });
            navLinks.appendChild(link);
        });
    }

    getNavigationForRole(role) {
        switch (role) {
            case 'end_user':
                return [
                    { label: 'Support Chat', view: 'chat-interface' },
                    { label: 'My Tickets', view: 'my-tickets' },
                    { label: 'Knowledge Base', view: 'knowledge-base' }
                ];
            case 'support_agent':
                return [
                    { label: 'Support Queue', view: 'agent-dashboard' },
                    { label: 'Knowledge Base', view: 'knowledge-base' }
                ];
            case 'admin':
                return [
                    { label: 'Dashboard', view: 'admin-dashboard' },
                    { label: 'All Tickets', view: 'all-tickets' },
                    { label: 'User Management', view: 'user-management' },
                    { label: 'Knowledge Base', view: 'knowledge-base' }
                ];
            default:
                return [];
        }
    }

    showDefaultView() {
        switch (this.currentUser.role) {
            case 'end_user':
                this.showView('chat-interface');
                break;
            case 'support_agent':
                this.showView('agent-dashboard');
                break;
            case 'admin':
                this.showView('admin-dashboard');
                break;
        }
    }

    showView(viewId) {
        // Hide all views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.add('hidden');
        });

        // Show selected view
        document.getElementById(viewId).classList.remove('hidden');
        
        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        
        const activeLink = Array.from(document.querySelectorAll('.nav-link'))
            .find(link => link.dataset.view === viewId);
        if (activeLink) {
            activeLink.classList.add('active');
        }

        this.currentView = viewId;

        // Load view-specific content
        switch (viewId) {
            case 'my-tickets':
                this.renderMyTickets();
                break;
            case 'agent-dashboard':
                this.renderAgentTickets();
                break;
            case 'admin-dashboard':
                this.renderAdminDashboard();
                break;
            case 'all-tickets':
                this.renderAllTickets();
                this.populateAdminFilters();
                break;
            case 'user-management':
                this.renderUserManagement();
                break;
            case 'knowledge-base':
                this.renderKnowledgeBase();
                break;
            case 'chat-interface':
                this.initializeChat();
                break;
        }
    }

    // Chat Session Management
    loadUserChatSessions() {
        const userSessions = this.getUserChatSessions();
        this.renderChatHistory(userSessions);
    }

    getUserChatSessions() {
        if (!this.chatSessions.has(this.currentUser.id)) {
            this.chatSessions.set(this.currentUser.id, []);
        }
        return this.chatSessions.get(this.currentUser.id);
    }

    createNewChatSession() {
        const session = {
            id: `session_${this.currentUser.id}_${this.nextSessionId++}`,
            userId: this.currentUser.id,
            title: 'New Chat',
            messages: [],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            isActive: true
        };
        
        const userSessions = this.getUserChatSessions();
        
        // Mark all other sessions as inactive
        userSessions.forEach(s => s.isActive = false);
        
        // Add new session
        userSessions.unshift(session);
        
        this.currentChatSession = session;
        this.sessionId = session.id;
        
        this.renderChatHistory(userSessions);
        return session;
    }

    switchToChatSession(sessionId) {
        const userSessions = this.getUserChatSessions();
        const session = userSessions.find(s => s.id === sessionId);
        
        if (!session) return;
        
        // Mark all sessions as inactive
        userSessions.forEach(s => s.isActive = false);
        
        // Activate selected session
        session.isActive = true;
        this.currentChatSession = session;
        this.sessionId = session.id;
        
        // Load chat messages
        this.loadChatMessages(session);
        this.renderChatHistory(userSessions);
    }

    loadChatMessages(session) {
        const messagesEl = document.getElementById('chat-messages');
        messagesEl.innerHTML = '';
        
        if (session.messages.length === 0) {
            this.addBotMessage("Hello! I'm here to help you with technical support. Please describe your issue and I'll try to find a solution for you.");
        } else {
            session.messages.forEach(message => {
                if (message.role === 'user') {
                    this.addUserMessage(message.content, false);
                } else {
                    this.addBotMessage(message.content, false);
                }
            });
        }
    }

    updateChatSessionTitle(sessionId, firstMessage) {
        const userSessions = this.getUserChatSessions();
        const session = userSessions.find(s => s.id === sessionId);
        
        if (session && session.title === 'New Chat') {
            // Generate title from first message (first 50 characters)
            const title = firstMessage.length > 50 
                ? firstMessage.substring(0, 50) + '...'
                : firstMessage;
            session.title = title;
            session.updatedAt = new Date().toISOString();
            this.renderChatHistory(this.getUserChatSessions());
        }
    }

    saveChatMessage(role, content) {
        if (!this.currentChatSession) {
            this.createNewChatSession();
        }
        
        const message = {
            role,
            content,
            timestamp: new Date().toISOString()
        };
        
        this.currentChatSession.messages.push(message);
        this.currentChatSession.updatedAt = new Date().toISOString();
        
        // Update title if this is the first user message
        if (role === 'user' && this.currentChatSession.messages.filter(m => m.role === 'user').length === 1) {
            this.updateChatSessionTitle(this.currentChatSession.id, content);
        }
    }

    deleteChatSession(sessionId) {
        const userSessions = this.getUserChatSessions();
        const sessionIndex = userSessions.findIndex(s => s.id === sessionId);
        
        if (sessionIndex === -1) return;
        
        const wasActive = userSessions[sessionIndex].isActive;
        userSessions.splice(sessionIndex, 1);
        
        // If we deleted the active session, switch to the most recent one or create new
        if (wasActive) {
            if (userSessions.length > 0) {
                this.switchToChatSession(userSessions[0].id);
            } else {
                this.startNewChat();
            }
        } else {
            this.renderChatHistory(userSessions);
        }
    }

    startNewChat() {
        this.createNewChatSession();
        const messagesEl = document.getElementById('chat-messages');
        messagesEl.innerHTML = '';
        this.addBotMessage("Hello! I'm here to help you with technical support. Please describe your issue and I'll try to find a solution for you.");
    }

    renderChatHistory(sessions) {
        const historyEl = document.getElementById('chat-history');
        
        if (sessions.length === 0) {
            historyEl.innerHTML = '<div class="chat-history-empty">No chat history yet</div>';
            return;
        }
        
        historyEl.innerHTML = sessions.map(session => `
            <div class="chat-history-item ${session.isActive ? 'active' : ''}" 
                 onclick="app.switchToChatSession('${session.id}')">
                <div class="chat-history-content">
                    <div class="chat-history-title">${this.escapeHtml(session.title)}</div>
                    <div class="chat-history-date">${this.formatDate(session.updatedAt)}</div>
                    <div class="chat-history-preview">
                        ${session.messages.length} messages
                    </div>
                </div>
                <button class="chat-history-delete" 
                        onclick="event.stopPropagation(); app.deleteChatSession('${session.id}')"
                        title="Delete chat">
                    ×
                </button>
            </div>
        `).join('');
    }
    // Chat Interface
    initializeChat() {
        // Load or create chat session
        const userSessions = this.getUserChatSessions();
        const activeSession = userSessions.find(s => s.isActive);
        
        if (activeSession) {
            this.currentChatSession = activeSession;
            this.sessionId = activeSession.id;
            this.loadChatMessages(activeSession);
        } else if (userSessions.length > 0) {
            // Switch to most recent session
            this.switchToChatSession(userSessions[0].id);
        } else {
            // Create first session
            this.startNewChat();
        }
    }

    async sendChatMessage() {
        const input = document.getElementById('chat-input');
        const message = input.value.trim();
        
        if (!message) return;

        this.addUserMessage(message);
        input.value = '';
        await this.processChatMessage(message);
    }

    addUserMessage(message, saveToHistory = true) {
        const messagesEl = document.getElementById('chat-messages');
        const messageEl = document.createElement('div');
        messageEl.className = 'message user';
        messageEl.innerHTML = `<div class="message-content">${this.escapeHtml(message)}</div>`;
        messagesEl.appendChild(messageEl);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        
        if (saveToHistory) {
            this.saveChatMessage('user', message);
        }
    }

    addBotMessage(message, includeTicketOption = false, saveToHistory = true) {
        const messagesEl = document.getElementById('chat-messages');
        const messageEl = document.createElement('div');
        messageEl.className = 'message bot';
        
        let content = `<div class="message-content">${this.escapeHtml(message)}</div>`;
        
        if (includeTicketOption) {
            content += `
                <div class="create-ticket-suggestion">
                    <p>If this doesn't resolve your issue, I can create a support ticket for you.</p>
                    <button class="btn btn--primary btn--sm create-ticket-btn">Create Ticket</button>
                </div>
            `;
        }
        
        messageEl.innerHTML = content;
        messagesEl.appendChild(messageEl);
        
        // Add event listener to create ticket button if it exists
        if (includeTicketOption) {
            const createTicketBtn = messageEl.querySelector('.create-ticket-btn');
            if (createTicketBtn) {
                createTicketBtn.addEventListener('click', () => {
                    this.showCreateTicketModal(message);
                });
            }
        }
        
        messagesEl.scrollTop = messagesEl.scrollHeight;
        
        if (saveToHistory) {
            this.saveChatMessage('assistant', message);
        }
    }

    async processChatMessage(message) {
        const lowerMessage = message.toLowerCase();
        
        // Search knowledge base for relevant solutions
        const relevantArticles = this.knowledgeBase.filter(article => 
            article.keywords.some(keyword => lowerMessage.includes(keyword.toLowerCase()))
        );

        if (relevantArticles.length > 0) {
            const article = relevantArticles[0];
            const response = `I found a solution for your issue:\n\n**${article.title}**\n\n${article.solution}`;
            this.addBotMessage(response, true);
        } else {
            // Call backend chatbot for further assistance
            try {
                const resp = await fetch('http://localhost:8000/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: message,
                        session_id: this.sessionId,
                        user_id: this.currentUser.id
                    })
                });
                const data = await resp.json();
                if (resp.ok) {
                    this.sessionId = data.session_id || this.sessionId;
                    this.addBotMessage(data.response || 'I could not generate a response.', true);
                } else {
                    this.addBotMessage('⚠️ The chatbot service returned an error. Please try again later.');
                }
            } catch (err) {
                console.error(err);
                const response = "I couldn't find a specific solution and the chatbot is unavailable. I can create a support ticket for you to get personalized help from our support team.";
                this.addBotMessage(response);
                setTimeout(() => {
                    this.showCreateTicketModal(message);
                }, 1500);
            }
        }
    }

    // Ticket Management
    showCreateTicketModal(description = '') {
        const modal = document.getElementById('create-ticket-modal');
        modal.classList.remove('hidden');
        
        if (description) {
            document.getElementById('ticket-description').value = description;
            // Auto-generate title from description
            const words = description.split(' ').slice(0, 6).join(' ');
            document.getElementById('ticket-title').value = words + (description.split(' ').length > 6 ? '...' : '');
        }
        
        // Auto-focus title field
        document.getElementById('ticket-title').focus();
    }

    createTicket() {
        const title = document.getElementById('ticket-title').value.trim();
        const description = document.getElementById('ticket-description').value.trim();
        const category = document.getElementById('ticket-category').value;
        const priority = document.getElementById('ticket-priority').value;

        if (!title || !description || !category) {
            alert('Please fill in all required fields.');
            return;
        }

        const department = this.getDepartmentForCategory(category);
        
        const ticket = {
            id: this.nextTicketId++,
            title,
            description,
            category,
            priority,
            status: 'Open',
            createdBy: this.currentUser.id,
            assignedTo: this.getAgentForDepartment(department),
            department,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            comments: []
        };

        this.tickets.push(ticket);
        this.closeModal('create-ticket-modal');
        
        // Show success message in chat
        this.addBotMessage(`Your ticket #${ticket.id} has been created successfully! It has been routed to the ${department} department and assigned for review.`);
        
        // Reset form
        document.getElementById('create-ticket-form').reset();
        
        // Refresh views if currently viewing tickets
        if (this.currentView === 'my-tickets') {
            this.renderMyTickets();
        }
    }

    getDepartmentForCategory(category) {
        const categoryLower = category.toLowerCase();
        for (const [keyword, dept] of Object.entries(this.routingRules)) {
            if (categoryLower.includes(keyword)) {
                return dept;
            }
        }
        return 'IT'; // Default department
    }

    getAgentForDepartment(department) {
        const agent = this.users.find(u => u.role === 'support_agent' && u.department === department);
        return agent ? agent.id : null;
    }

    renderMyTickets() {
        const container = document.getElementById('my-tickets-list');
        const userTickets = this.tickets.filter(t => t.createdBy === this.currentUser.id);
        
        if (userTickets.length === 0) {
            container.innerHTML = '<p class="text-center">You have no tickets yet. Start a conversation in the Support Chat to get help with your technical issues.</p>';
            return;
        }

        container.innerHTML = userTickets.map(ticket => this.createTicketCard(ticket)).join('');
    }

    renderAgentTickets() {
        const container = document.getElementById('agent-tickets-list');
        const statusFilter = document.getElementById('status-filter')?.value || '';
        const priorityFilter = document.getElementById('priority-filter')?.value || '';
        
        // Show tickets assigned to this agent OR unassigned tickets in their department
        let agentTickets = this.tickets.filter(t => 
            (t.department === this.currentUser.department || 
             t.assignedTo === this.currentUser.id) && 
            t.status !== 'Closed'
        );

        if (statusFilter) {
            agentTickets = agentTickets.filter(t => t.status === statusFilter);
        }
        
        if (priorityFilter) {
            agentTickets = agentTickets.filter(t => t.priority === priorityFilter);
        }

        if (agentTickets.length === 0) {
            container.innerHTML = '<p class="text-center">No tickets in your queue. New tickets will appear here when they are assigned to your department.</p>';
            return;
        }

        container.innerHTML = agentTickets.map(ticket => this.createTicketCard(ticket, true)).join('');
    }

    renderAllTickets() {
        const container = document.getElementById('all-tickets-list');
        const statusFilter = document.getElementById('admin-status-filter')?.value || '';
        const departmentFilter = document.getElementById('admin-department-filter')?.value || '';
        
        let allTickets = [...this.tickets];

        if (statusFilter) {
            allTickets = allTickets.filter(t => t.status === statusFilter);
        }
        
        if (departmentFilter) {
            allTickets = allTickets.filter(t => t.department === departmentFilter);
        }

        if (allTickets.length === 0) {
            container.innerHTML = '<p class="text-center">No tickets found.</p>';
            return;
        }

        container.innerHTML = allTickets.map(ticket => this.createTicketCard(ticket, true)).join('');
    }

    createTicketCard(ticket, showActions = false) {
        const creator = this.users.find(u => u.id === ticket.createdBy);
        const assignee = ticket.assignedTo ? this.users.find(u => u.id === ticket.assignedTo) : null;
        
        return `
            <div class="ticket-card" onclick="app.showTicketDetails(${ticket.id})">
                <div class="ticket-header">
                    <div>
                        <p class="ticket-id">Ticket #${ticket.id}</p>
                        <h4 class="ticket-title">${this.escapeHtml(ticket.title)}</h4>
                    </div>
                    <div class="status ${ticket.status.toLowerCase().replace(' ', '-')}">${ticket.status}</div>
                </div>
                <p class="ticket-description">${this.escapeHtml(ticket.description)}</p>
                <div class="ticket-meta">
                    <div class="ticket-info">
                        <span><strong>Priority:</strong> <span class="status priority-${ticket.priority.toLowerCase()}">${ticket.priority}</span></span>
                        <span><strong>Department:</strong> ${ticket.department}</span>
                        <span><strong>Created:</strong> ${this.formatDate(ticket.createdAt)}</span>
                        ${creator ? `<span><strong>By:</strong> ${creator.name}</span>` : ''}
                        ${assignee ? `<span><strong>Assigned:</strong> ${assignee.name}</span>` : '<span><strong>Status:</strong> Unassigned</span>'}
                    </div>
                </div>
            </div>
        `;
    }

    showTicketDetails(ticketId) {
        const ticket = this.tickets.find(t => t.id === ticketId);
        if (!ticket) return;

        const modal = document.getElementById('ticket-modal');
        const titleEl = document.getElementById('ticket-modal-title');
        const bodyEl = document.getElementById('ticket-modal-body');

        titleEl.textContent = `Ticket #${ticket.id} - ${ticket.title}`;
        
        const creator = this.users.find(u => u.id === ticket.createdBy);
        const assignee = ticket.assignedTo ? this.users.find(u => u.id === ticket.assignedTo) : null;

        let actionsHtml = '';
        if (this.currentUser.role === 'support_agent' || this.currentUser.role === 'admin') {
            const statusOptions = ['Open', 'In Progress', 'Resolved', 'Closed'];
            const priorityOptions = ['Low', 'Medium', 'High', 'Critical'];
            
            actionsHtml = `
                <div class="ticket-actions">
                    <select id="update-status" class="form-control">
                        ${statusOptions.map(status => 
                            `<option value="${status}" ${ticket.status === status ? 'selected' : ''}>${status}</option>`
                        ).join('')}
                    </select>
                    <select id="update-priority" class="form-control">
                        ${priorityOptions.map(priority => 
                            `<option value="${priority}" ${ticket.priority === priority ? 'selected' : ''}>${priority}</option>`
                        ).join('')}
                    </select>
                    <button onclick="app.updateTicket(${ticket.id})" class="btn btn--primary">Update</button>
                </div>
                <div class="form-group mt-16">
                    <label class="form-label">Add Comment</label>
                    <textarea id="new-comment" class="form-control" rows="3" placeholder="Add a comment..."></textarea>
                    <div class="mt-16">
                        <label>
                            <input type="checkbox" id="internal-comment"> Internal comment (not visible to end user)
                        </label>
                    </div>
                    <button onclick="app.addComment(${ticket.id})" class="btn btn--secondary mt-16">Add Comment</button>
                </div>
            `;
        }

        bodyEl.innerHTML = `
            <div class="ticket-details">
                <div class="detail-section">
                    <h4>Ticket Information</h4>
                    <div class="detail-grid">
                        <div class="detail-item">
                            <span class="detail-label">Status</span>
                            <span class="detail-value status ${ticket.status.toLowerCase().replace(' ', '-')}">${ticket.status}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Priority</span>
                            <span class="detail-value status priority-${ticket.priority.toLowerCase()}">${ticket.priority}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Category</span>
                            <span class="detail-value">${ticket.category}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Department</span>
                            <span class="detail-value">${ticket.department}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created By</span>
                            <span class="detail-value">${creator ? creator.name : 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Assigned To</span>
                            <span class="detail-value">${assignee ? assignee.name : 'Unassigned'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created</span>
                            <span class="detail-value">${this.formatDate(ticket.createdAt)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Last Updated</span>
                            <span class="detail-value">${this.formatDate(ticket.updatedAt)}</span>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <h4>Description</h4>
                    <p>${this.escapeHtml(ticket.description)}</p>
                </div>
                
                ${ticket.comments.length > 0 ? `
                    <div class="detail-section">
                        <h4>Comments</h4>
                        ${ticket.comments.map(comment => {
                            const author = this.users.find(u => u.id === comment.authorId);
                            return `
                                <div class="comment ${comment.internal ? 'internal' : ''}">
                                    <div class="comment-header">
                                        <span class="comment-author">${author ? author.name : 'Unknown'}</span>
                                        <span class="comment-date">${this.formatDate(comment.createdAt)}</span>
                                        ${comment.internal ? '<span class="status warning">Internal</span>' : ''}
                                    </div>
                                    <p class="comment-content">${this.escapeHtml(comment.content)}</p>
                                </div>
                            `;
                        }).join('')}
                    </div>
                ` : ''}
                
                ${actionsHtml}
            </div>
        `;

        modal.classList.remove('hidden');
    }

    updateTicket(ticketId) {
        const ticket = this.tickets.find(t => t.id === ticketId);
        if (!ticket) return;

        const newStatus = document.getElementById('update-status').value;
        const newPriority = document.getElementById('update-priority').value;

        ticket.status = newStatus;
        ticket.priority = newPriority;
        ticket.updatedAt = new Date().toISOString();

        if (!ticket.assignedTo && this.currentUser.role === 'support_agent') {
            ticket.assignedTo = this.currentUser.id;
        }

        this.closeModal('ticket-modal');
        this.refreshCurrentView();
    }

    addComment(ticketId) {
        const ticket = this.tickets.find(t => t.id === ticketId);
        if (!ticket) return;

        const content = document.getElementById('new-comment').value.trim();
        const internal = document.getElementById('internal-comment').checked;

        if (!content) return;

        const comment = {
            id: Date.now(),
            authorId: this.currentUser.id,
            content,
            internal,
            createdAt: new Date().toISOString()
        };

        ticket.comments.push(comment);
        ticket.updatedAt = new Date().toISOString();

        // Refresh the modal
        this.showTicketDetails(ticketId);
    }

    // Admin Dashboard
    renderAdminDashboard() {
        // Update statistics
        document.getElementById('total-tickets').textContent = this.tickets.length;
        document.getElementById('open-tickets').textContent = 
            this.tickets.filter(t => t.status === 'Open').length;
        document.getElementById('resolved-tickets').textContent = 
            this.tickets.filter(t => t.status === 'Resolved').length;

        // Department statistics
        const deptStats = document.getElementById('department-stats');
        const deptCounts = {};
        
        this.departments.forEach(dept => {
            deptCounts[dept.name] = this.tickets.filter(t => 
                t.department === dept.name && t.status !== 'Closed'
            ).length;
        });

        deptStats.innerHTML = Object.entries(deptCounts)
            .map(([dept, count]) => `
                <div class="department-stat">
                    <span>${dept}</span>
                    <span><strong>${count}</strong> open tickets</span>
                </div>
            `).join('');
    }

    populateAdminFilters() {
        const deptFilter = document.getElementById('admin-department-filter');
        if (deptFilter && deptFilter.children.length <= 1) {
            this.departments.forEach(dept => {
                const option = document.createElement('option');
                option.value = dept.name;
                option.textContent = dept.name;
                deptFilter.appendChild(option);
            });
        }
    }

    // User Management
    renderUserManagement() {
        const container = document.getElementById('users-list');
        
        container.innerHTML = this.users.map(user => `
            <div class="user-card">
                <div class="user-info">
                    <h4>${user.name}</h4>
                    <p>${user.email} • ${this.formatRole(user.role)} • ${user.department}</p>
                    <p><strong>Username:</strong> ${user.username} • <strong>Status:</strong> ${user.active ? 'Active' : 'Inactive'}</p>
                </div>
                <div class="user-actions">
                    <button onclick="app.toggleUserStatus(${user.id})" 
                            class="btn ${user.active ? 'btn--secondary' : 'btn--primary'} btn--sm">
                        ${user.active ? 'Deactivate' : 'Activate'}
                    </button>
                </div>
            </div>
        `).join('');
    }

    showAddUserModal() {
        const modal = document.getElementById('add-user-modal');
        const deptSelect = document.getElementById('new-department');
        
        // Populate departments
        deptSelect.innerHTML = '';
        this.departments.forEach(dept => {
            const option = document.createElement('option');
            option.value = dept.name;
            option.textContent = dept.name;
            deptSelect.appendChild(option);
        });

        modal.classList.remove('hidden');
        document.getElementById('new-username').focus();
    }

    addUser() {
        const username = document.getElementById('new-username').value;
        const name = document.getElementById('new-name').value;
        const email = document.getElementById('new-email').value;
        const role = document.getElementById('new-role').value;
        const department = document.getElementById('new-department').value;

        // Check if username already exists
        if (this.users.some(u => u.username === username)) {
            alert('Username already exists');
            return;
        }

        const newUser = {
            id: this.nextUserId++,
            username,
            password: 'password123', // Default password
            role,
            name,
            department,
            email,
            active: true
        };

        this.users.push(newUser);
        this.closeModal('add-user-modal');
        document.getElementById('add-user-form').reset();
        this.renderUserManagement();
    }

    toggleUserStatus(userId) {
        const user = this.users.find(u => u.id === userId);
        if (user && user.id !== this.currentUser.id) { // Can't deactivate self
            user.active = !user.active;
            this.renderUserManagement();
        }
    }

    // Utility Methods
    closeModal(modalId) {
        document.getElementById(modalId).classList.add('hidden');
    }

    refreshCurrentView() {
        if (this.currentView) {
            this.showView(this.currentView);
        }
    }

    formatRole(role) {
        return role.split('_').map(word => 
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }

    formatDate(dateString) {
        return new Date(dateString).toLocaleString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

}
window.app = new BankingSupportApp();