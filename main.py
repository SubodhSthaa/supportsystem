from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
import sqlite3
import uuid
import logging
import json
from datetime import datetime
from typing import Optional
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
import secrets
from dotenv import load_dotenv

load_dotenv()

# ----------------------------
# Config
# ----------------------------
LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
MODEL_NAME = "openai/gpt-oss-20b"
MAX_HISTORY_MESSAGES = 10
MAX_TOKENS = 2048

# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------------------
# App initialization
# ----------------------------
app = FastAPI(title="Support Chatbot API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Database setup
# ----------------------------
DB_FILE = "support_system.db"

def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Tickets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            email TEXT NOT NULL,
            type TEXT NOT NULL,
            description TEXT NOT NULL,
            session_id TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Chat sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_sessions (
            id TEXT PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Users table for Google SSO
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            picture TEXT,
            role TEXT DEFAULT 'end_user',
            department TEXT DEFAULT 'General',
            active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Insert default admin user if not exists
    cursor.execute("""
        INSERT OR IGNORE INTO users (email, name, role, department, google_id)
        VALUES ('admin@company.com', 'System Administrator', 'admin', 'Administration', 'local_admin')
    """)
    
    # Chat history table (linked to sessions)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            user_id INTEGER,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES chat_sessions (id)
        )
    """)
    
    # Create indexes for better performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_history_session ON chat_history(session_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chat_history_user ON chat_history(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_type ON tickets(type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id)")
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

init_db()

# ----------------------------
# Data models
# ----------------------------
class ChatMessage(BaseModel):
    message: str
    session_id: Optional[str] = None
    user_id: Optional[int] = None

class TicketCreate(BaseModel):
    user: str
    email: str
    type: str
    description: str
    session_id: Optional[str] = None

class GoogleAuthRequest(BaseModel):
    credential: str

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    picture: Optional[str]
    role: str
    department: str
    active: bool

# ----------------------------
# Helper functions
# ----------------------------
def get_or_create_session(session_id: str) -> str:
    """Get existing session or create new one"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Check if session exists
    cursor.execute("SELECT id FROM chat_sessions WHERE id = ?", (session_id,))
    if not cursor.fetchone():
        # Create new session
        cursor.execute(
            "INSERT INTO chat_sessions (id) VALUES (?)", 
            (session_id,)
        )
        logger.info(f"Created new session: {session_id}")
    else:
        # Update last activity
        cursor.execute(
            "UPDATE chat_sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = ?",
            (session_id,)
        )
    
    conn.commit()
    conn.close()
    return session_id

def get_session_history(session_id: str) -> list:
    """Get chat history for a specific session"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT role, content FROM chat_history 
        WHERE session_id = ? 
        ORDER BY timestamp ASC
    """, (session_id,))
    
    history = [{"role": row[0], "content": row[1]} for row in cursor.fetchall()]
    conn.close()
    return history

def save_message_to_history(session_id: str, role: str, content: str, user_id: Optional[int] = None):
    """Save a message to chat history"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO chat_history (session_id, user_id, role, content) 
        VALUES (?, ?, ?, ?)
    """, (session_id, user_id, role, content))
    
    conn.commit()
    conn.close()

def classify_issue_type(message: str) -> str:
    """Classify the issue type based on message content"""
    message_lower = message.lower()
    
    # E-Banking keywords
    ebanking_keywords = [
        'bank', 'banking', 'account', 'balance', 'transaction', 'transfer',
        'payment', 'card', 'atm', 'online banking', 'mobile banking',
        'deposit', 'withdrawal', 'loan', 'credit', 'debit'
    ]
    
    # IT Support keywords
    it_keywords = [
        'password', 'login', 'computer', 'laptop', 'software', 'hardware',
        'network', 'wifi', 'internet', 'email', 'printer', 'system',
        'error', 'bug', 'crash', 'slow', 'virus', 'security', 'backup'
    ]
    
    # Count keyword matches
    ebanking_score = sum(1 for keyword in ebanking_keywords if keyword in message_lower)
    it_score = sum(1 for keyword in it_keywords if keyword in message_lower)
    
    if ebanking_score > it_score and ebanking_score > 0:
        return "E-Banking"
    elif it_score > 0:
        return "IT Support"
    else:
        return "General"

async def get_ai_response(message: str, chat_history: list) -> tuple[str, str]:
    """Get AI response from LM Studio"""
    try:
        # Prepare system prompt for IT support context
        system_prompt = """You are a helpful IT Support Assistant. Your role is to:

1. Provide clear, step-by-step solutions for technical problems
2. Ask clarifying questions when needed
3. Be professional but friendly
4. Focus on IT support, e-banking issues, and general technical help
5. Keep responses concise but comprehensive
6. If you cannot solve an issue completely, acknowledge it and suggest creating a support ticket

Common areas you help with:
- Password resets and login issues
- Software troubleshooting
- Hardware problems
- Network connectivity
- E-banking and online banking issues
- Email and communication tools
- System performance issues

Always be helpful and solution-oriented."""

        # Build conversation history
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add recent chat history (limit to prevent token overflow)
        recent_history = chat_history[-MAX_HISTORY_MESSAGES:] if len(chat_history) > MAX_HISTORY_MESSAGES else chat_history
        messages.extend(recent_history)
        
        # Add current user message
        messages.append({"role": "user", "content": message})

        payload = {
            "model": MODEL_NAME,
            "messages": messages,
            "max_tokens": MAX_TOKENS,
            "temperature": 0.7,
            "stream": False
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(LMSTUDIO_URL, json=payload)
            response.raise_for_status()
            result = response.json()

        # Extract response content
        choice = result["choices"][0]["message"]
        ai_response = choice.get("content") or choice.get("reasoning_content") or "I apologize, but I couldn't generate a proper response. Please try rephrasing your question."
        
        # Classify the issue type
        issue_type = classify_issue_type(message)
        
        logger.info(f"AI response generated successfully. Issue type: {issue_type}")
        return ai_response, issue_type

    except httpx.TimeoutException:
        logger.error("LM Studio request timed out")
        return "⚠️ The AI service is taking too long to respond. Please try again in a moment.", "General"
    except httpx.HTTPStatusError as e:
        logger.error(f"LM Studio HTTP error: {e.response.status_code}")
        return "⚠️ The AI service is currently unavailable. Please try again later.", "General"
    except Exception as e:
        logger.error(f"Unexpected error in AI response: {str(e)}")
        return "⚠️ I encountered an unexpected error. Please try again or contact support if the issue persists.", "General"

# ----------------------------
# API Endpoints
# ----------------------------
@app.get("/")
async def get_index():
    """Serve the main HTML page"""
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return JSONResponse({"error": "index.html not found"}, status_code=404)

@app.get("/app.js")
async def get_app_js():
    """Serve the main JavaScript file"""
    if os.path.exists("app.js"):
        return FileResponse("app.js", media_type="application/javascript")
    return JSONResponse({"error": "app.js not found"}, status_code=404)

@app.get("/style.css")
async def get_style_css():
    """Serve the main CSS file"""
    if os.path.exists("style.css"):
        return FileResponse("style.css", media_type="text/css")
    return JSONResponse({"error": "style.css not found"}, status_code=404)

@app.post("/chat")
async def chat_endpoint(data: ChatMessage, request: Request):
    """Handle chat messages"""
    try:
        # Get or create session
        session_id = data.session_id or request.headers.get("Session-ID", f"session_{uuid.uuid4()}")
        session_id = get_or_create_session(session_id)
        
        # Get chat history for this session
        chat_history = get_session_history(session_id)
        
        # Get AI response
        ai_response, issue_type = await get_ai_response(data.message, chat_history)
        
        # Save both user message and AI response to history
        save_message_to_history(session_id, "user", data.message, data.user_id)
        save_message_to_history(session_id, "assistant", ai_response, data.user_id)
        
        logger.info(f"Chat processed for session {session_id[:8]}... - Issue type: {issue_type}")
        
        return JSONResponse({
            "response": ai_response,
            "category": issue_type,
            "session_id": session_id
        })
        
    except Exception as e:
        logger.error(f"Error in chat endpoint: {str(e)}")
        return JSONResponse(
            {"error": "Internal server error", "response": "⚠️ Sorry, I encountered an error. Please try again."},
            status_code=500
        )

@app.post("/ticket")
async def create_ticket(ticket_data: dict):
    """Create a new support ticket"""
    try:
        # Generate unique ticket ID
        ticket_id = f"TKT-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
        
        # Validate required fields
        required_fields = ['user', 'email', 'type', 'description']
        for field in required_fields:
            if field not in ticket_data or not ticket_data[field].strip():
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Insert ticket into database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO tickets (id, user, email, type, description, session_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            ticket_id,
            ticket_data['user'].strip(),
            ticket_data['email'].strip(),
            ticket_data['type'].strip(),
            ticket_data['description'].strip(),
            ticket_data.get('session_id'),
            'open'
        ))
        
        conn.commit()
        conn.close()
        
        # Prepare response
        ticket_response = {
            "id": ticket_id,
            "user": ticket_data['user'],
            "email": ticket_data['email'],
            "type": ticket_data['type'],
            "description": ticket_data['description'],
            "status": "open",
            "created_at": datetime.now().isoformat()
        }
        
        logger.info(f"Ticket created: {ticket_id} for {ticket_data['email']}")
        
        return JSONResponse({
            "message": "Ticket created successfully!",
            "ticket": ticket_response
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating ticket: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create ticket")

@app.get("/tickets")
async def list_tickets():
    """Get all tickets"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, user, email, type, description, status, created_at, updated_at
            FROM tickets 
            ORDER BY created_at DESC
        """)
        
        tickets = []
        for row in cursor.fetchall():
            tickets.append({
                "id": row[0],
                "user": row[1],
                "email": row[2],
                "type": row[3],
                "description": row[4],
                "status": row[5],
                "created_at": row[6],
                "updated_at": row[7]
            })
        
        conn.close()
        
        return JSONResponse({"tickets": tickets})
        
    except Exception as e:
        logger.error(f"Error fetching tickets: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch tickets")

@app.get("/sessions/{session_id}/history")
async def get_session_chat_history(session_id: str):
    """Get chat history for a specific session"""
    try:
        history = get_session_history(session_id)
        return JSONResponse({
            "session_id": session_id,
            "history": history
        })
    except Exception as e:
        logger.error(f"Error fetching session history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch session history")

@app.get("/users/{user_id}/sessions")
async def get_user_sessions(user_id: int):
    """Get all chat sessions for a specific user"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT DISTINCT ch.session_id, cs.created_at, cs.last_activity,
                   COUNT(ch.id) as message_count,
                   MIN(CASE WHEN ch.role = 'user' THEN ch.content END) as first_message
            FROM chat_history ch
            JOIN chat_sessions cs ON ch.session_id = cs.id
            WHERE ch.user_id = ?
            GROUP BY ch.session_id, cs.created_at, cs.last_activity
            ORDER BY cs.last_activity DESC
        """, (user_id,))
        
        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                "session_id": row[0],
                "created_at": row[1],
                "last_activity": row[2],
                "message_count": row[3],
                "first_message": row[4] or "New Chat"
            })
        
        conn.close()
        
        return JSONResponse({
            "user_id": user_id,
            "sessions": sessions
        })
        
    except Exception as e:
        logger.error(f"Error fetching user sessions: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch user sessions")

def create_jwt_token(user_data: dict) -> str:
    """Create a simple JWT-like token for the user"""
    import base64
    import hmac
    import hashlib
    
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {
        "user_id": user_data["id"],
        "email": user_data["email"],
        "name": user_data["name"],
        "role": user_data["role"],
        "exp": int(datetime.now().timestamp()) + (24 * 60 * 60)  # 24 hours
    }
    
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    signature = hmac.new(
        JWT_SECRET.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"

def get_or_create_user(google_user_info: dict) -> dict:
    """Get existing user or create new one from Google user info"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Try to find existing user by Google ID or email
    cursor.execute("""
        SELECT id, google_id, email, name, picture, role, department, active
        FROM users 
        WHERE google_id = ? OR email = ?
    """, (google_user_info["sub"], google_user_info["email"]))
    
    user = cursor.fetchone()
    
    if user:
        # Update existing user info
        cursor.execute("""
            UPDATE users 
            SET google_id = ?, name = ?, picture = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (google_user_info["sub"], google_user_info["name"], 
              google_user_info.get("picture"), user[0]))
        
        user_data = {
            "id": user[0],
            "google_id": google_user_info["sub"],
            "email": user[2],
            "name": google_user_info["name"],
            "picture": google_user_info.get("picture"),
            "role": user[5],
            "department": user[6],
            "active": bool(user[7])
        }
    else:
        # Create new user
        # Determine role based on email domain or default to end_user
        role = "admin" if google_user_info["email"].endswith("@company.com") else "end_user"
        department = "Administration" if role == "admin" else "General"
        
        cursor.execute("""
            INSERT INTO users (google_id, email, name, picture, role, department)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (google_user_info["sub"], google_user_info["email"], 
              google_user_info["name"], google_user_info.get("picture"), 
              role, department))
        
        user_id = cursor.lastrowid
        user_data = {
            "id": user_id,
            "google_id": google_user_info["sub"],
            "email": google_user_info["email"],
            "name": google_user_info["name"],
            "picture": google_user_info.get("picture"),
            "role": role,
            "department": department,
            "active": True
        }
    
    conn.commit()
    conn.close()
    
    return user_data

@app.post("/auth/google")
async def google_auth(auth_request: GoogleAuthRequest):
    """Handle Google OAuth authentication"""
    try:
        # Verify the Google ID token
        idinfo = id_token.verify_oauth2_token(
            auth_request.credential, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        # Get or create user
        user_data = get_or_create_user(idinfo)
        
        if not user_data["active"]:
            raise HTTPException(status_code=403, detail="Account is deactivated")
        
        # Create JWT token
        token = create_jwt_token(user_data)
        
        logger.info(f"Google SSO login successful for {user_data['email']}")
        
        return JSONResponse({
            "success": True,
            "token": token,
            "user": {
                "id": user_data["id"],
                "email": user_data["email"],
                "name": user_data["name"],
                "picture": user_data["picture"],
                "role": user_data["role"],
                "department": user_data["department"]
            }
        })
        
    except ValueError as e:
        logger.error(f"Invalid Google token: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid Google token")
    except Exception as e:
        logger.error(f"Google auth error: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@app.get("/auth/config")
async def get_auth_config():
    """Get authentication configuration for frontend"""
    # Only enable Google SSO if we have a real client ID (not empty or demo)
    google_enabled = (
        bool(GOOGLE_CLIENT_ID) and 
        GOOGLE_CLIENT_ID != "demo-google-client-id.apps.googleusercontent.com" and
        len(GOOGLE_CLIENT_ID.strip()) > 0 and
        GOOGLE_CLIENT_ID.endswith('.apps.googleusercontent.com')
    )
    
    return JSONResponse({
        "google_client_id": GOOGLE_CLIENT_ID,
        "google_enabled": google_enabled
    })

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })

# ----------------------------
# Error handlers
# ----------------------------
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Endpoint not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")