from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
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
import base64
import hmac
import hashlib
import re

load_dotenv()

# ----------------------------
# Config
# ----------------------------
LMSTUDIO_URL = "http://localhost:1030/v1/chat/completions"
MODEL_NAME = "openai/gpt-oss-20b"
MAX_HISTORY_MESSAGES = 10
MAX_TOKENS = 612

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
# Security
# ----------------------------
security = HTTPBearer()

def verify_jwt_token(token: str) -> dict:
    """Verify JWT token and return payload"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise HTTPException(status_code=401, detail="Invalid token format")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Recreate signature
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(
            JWT_SECRET.encode(),
            message,
            hashlib.sha256
        ).digest()
        expected_signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        if signature_b64 != expected_signature_b64:
            raise HTTPException(status_code=401, detail="Invalid token signature")
        
        # Decode payload
        payload_json = base64.urlsafe_b64decode(payload_b64 + '=' * (-len(payload_b64) % 4))
        payload = json.loads(payload_json)
        
        # Check expiration
        if payload.get("exp", 0) < datetime.now().timestamp():
            raise HTTPException(status_code=401, detail="Token expired")
        
        return payload
        
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    token = credentials.credentials
    payload = verify_jwt_token(token)
    return payload

def require_admin(user: dict = Depends(get_current_user)):
    """Require admin role"""
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return user

# ----------------------------
# Database setup
# ----------------------------
DB_FILE = "support_system.db"

def init_db():
    """Initialize or synchronize database tables without overwriting KB."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        # ------------------------
        # Core tables
        # ------------------------
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

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_sessions (
                id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

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
        
        # Ensure admin user exists
        cursor.execute("""
            INSERT OR IGNORE INTO users (email, name, role, department, google_id)
            VALUES ('admin@company.com', 'System Administrator', 'admin', 'Administration', 'local_admin')
        """)

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

        # ------------------------
        # Knowledge base & routing tables
        # ------------------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                solution TEXT NOT NULL,
                keywords TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS routing_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyword TEXT UNIQUE NOT NULL,
                department TEXT NOT NULL
            )
        """)
        
        # Add admin_audit_log table for tracking admin actions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id INTEGER,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_user_id) REFERENCES users (id)
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kb_title ON knowledge_base(title)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kb_category ON knowledge_base(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")

        # ------------------------
        # Default Routing Rules
        # ------------------------
        default_routing_rules = [
            ("hardware", "IT"),
            ("software", "IT"),
            ("network", "IT"),
            ("password", "IT"),
            ("authentication", "IT"),
            ("digital banking", "Digital Banking"),
            ("mobile app", "Digital Banking"),
            ("core banking", "Operations"),
            ("teller", "Operations"),
            ("compliance", "AML/CFT"),
            ("loan", "Loan")
        ]

        cursor.execute("SELECT keyword FROM routing_rules")
        existing_keywords = {row[0] for row in cursor.fetchall()}

        for keyword, department in default_routing_rules:
            if keyword in existing_keywords:
                cursor.execute("""
                    UPDATE routing_rules
                    SET department = ?
                    WHERE keyword = ?
                """, (department, keyword))
            else:
                cursor.execute("""
                    INSERT INTO routing_rules (keyword, department)
                    VALUES (?, ?)
                """, (keyword, department))

        # Optional: delete old routing rules not in default list
        default_keywords = {r[0] for r in default_routing_rules}
        cursor.execute(
            "DELETE FROM routing_rules WHERE keyword NOT IN ({})".format(
                ",".join("?" * len(default_keywords))
            ),
            tuple(default_keywords)
        )

        conn.commit()
        logger.info("✅ Database initialized and synchronized successfully (KB preserved).")

    except Exception as e:
        logger.error(f"❌ Error initializing database: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_knowledge_base():
    """Fetch all knowledge base entries from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, category, solution, keywords FROM knowledge_base ORDER BY id")
    rows = cursor.fetchall()
    conn.close()

    # Convert rows to list of dictionaries
    knowledge_base = [
        {
            "id": row[0],
            "title": row[1],
            "category": row[2],
            "solution": row[3],
            "keywords": [kw.strip() for kw in row[4].split(",")] if row[4] else []
        }
        for row in rows
    ]
    return knowledge_base

# Initialize DB on startup
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

def search_knowledge_base(query: str):
    """Search knowledge base for matching keywords or title."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    like_term = f"%{query.lower()}%"
    cursor.execute("""
        SELECT title, category, solution, keywords
        FROM knowledge_base
        WHERE lower(title) LIKE ? OR lower(solution) LIKE ? OR lower(keywords) LIKE ?
        ORDER BY updated_at DESC
    """, (like_term, like_term, like_term))
    results = cursor.fetchall()
    conn.close()
    return [{"title": r[0], "category": r[1], "solution": r[2], "keywords": r[3]} for r in results]

def get_department_for_keyword(keyword: str) -> str:
    """Get department routing based on keyword."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT department FROM routing_rules WHERE lower(keyword) = ?", (keyword.lower(),))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else "General"

def validate_response(response: str) -> bool:
    """Validate that the AI response is clean and meaningful"""
    # Check for common gibberish indicators
    gibberish_indicators = [
        'VIDEO', 'breaking', 'commentators', '2023', '16 Hours',
        'fit by us', 'DSCAPUT', 'OPAT', 'C-aunchy', 'bookstore USB'
    ]
    
    if any(indicator in response for indicator in gibberish_indicators):
        return False
    
    # Check response length and quality
    if len(response.strip()) < 20:
        return False
        
    # Check for reasonable word length and structure
    words = response.split()
    if len(words) < 5:
        return False
        
    return True

def clean_ai_response(response: str) -> str:
    """Clean and format AI responses to remove gibberish and random symbols"""
    # Remove random symbols and gibberish patterns
    cleaned = response
    
    # Remove common gibberish patterns
    gibberish_patterns = [
        r'\*.*?\*',  # Remove content between asterisks
        r'\(.*?\)',  # Remove content in parentheses that might be gibberish
        r'[^\w\s.,!?;:()\-@#$/]',  # Keep only common punctuation
        r'\b(\w*[0-9]+\w*)\b',  # Remove words with numbers mixed in
        r'_{2,}',  # Remove double underscores and more
    ]
    
    for pattern in gibberish_patterns:
        cleaned = re.sub(pattern, '', cleaned)
    
    # Fix common OCR/formatting issues
    replacements = {
        'fit by us that is solution': 'we will find a solution',
        'DSCAPUT': 'BIOS/UEFI',
        'OPAT': 'DVD',
        'C-aunchy': 'clean',
        'bookstore USB': 'bootable USB',
        'portfetch': 'partition',
        'Ax4': 'F12',
        '1/2': 'F2',
    }
    
    for wrong, correct in replacements.items():
        cleaned = cleaned.replace(wrong, correct)
    
    # Remove extra whitespace and clean up formatting
    cleaned = re.sub(r'\s+', ' ', cleaned)  # Replace multiple spaces with single space
    cleaned = re.sub(r'\.\s+\.', '.', cleaned)  # Fix multiple dots
    cleaned = cleaned.strip()
    
    return cleaned

def format_ai_response(response: str) -> str:
    """Ensure AI responses follow clean formatting standards"""
    # First clean the response
    cleaned_response = clean_ai_response(response)
    
    # Structure the response properly
    lines = cleaned_response.split('\n')
    formatted_lines = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Skip lines that are likely gibberish
        if len(line) < 3 or any(word in line.lower() for word in ['video', 'breaking', 'commentators']):
            continue
            
        # Format bullet points properly
        if line.startswith(('-', '•', '*')) and len(line) > 3:
            formatted_lines.append(f"• {line[1:].strip()}")
        elif re.match(r'^\d+[\.\)]', line):  # Numbered lists
            formatted_lines.append(line)
        elif len(line) > 20:  # Only include substantial lines
            formatted_lines.append(line)
    
    # Join with proper spacing
    formatted = '\n\n'.join(formatted_lines)
    
    # Ensure it ends with engagement
    if not any(phrase in formatted.lower() for phrase in 
               ['let me know', 'please share', 'tell me', 'keep me updated', 'update me']):
        formatted += "\n\nLet me know if this helps or if you need more specific guidance!"
    
    return formatted

async def get_ai_response(message: str, chat_history: list) -> tuple[str, str]:
    """Get AI response from LM Studio"""
    try:
        system_prompt = """You are a helpful IT Support Assistant. Follow these strict rules:

**RESPONSE QUALITY RULES:**
1. Keep responses SHORT and CONCISE - maximum 3-4 sentences
2. NEVER include random symbols, gibberish, or nonsensical text
3. NEVER include timestamps, video references, or unrelated metadata
4. ALWAYS use proper English with correct grammar and spelling
5. ALWAYS provide clear, actionable information
6. NEVER make up technical terms or use incorrect terminology
7. NEVER use underscores (_) in your responses
8. Get straight to the point - no long introductions

**RESPONSE LENGTH RULES:**
- Maximum 150 words total
- Use 1-2 short paragraphs maximum
- Use bullet points only for key steps (max 3-4 bullets)
- No lengthy explanations - be direct and helpful

**RESPONSE STRUCTURE:**
1. Brief empathy statement (1 sentence)
2. Direct solution or clarifying question
3. 1-3 key steps if needed
4. Offer further help

**EXAMPLES OF GOOD SHORT RESPONSES:**

**Example 1:**
I understand your printer isn't working. Let's try these quick fixes:
• Restart the printer and computer
• Check cable connections
• Update printer drivers
Let me know if this helps or if you need more specific guidance.

**Example 2:**
For Windows installation issues, I need to know:
• Which Windows version?
• Installation method (USB/DVD)?
• Any error messages?
This will help me provide the exact steps you need.

**Example 3:**
Try resetting your password at portal.company.com. If that doesn't work, contact IT support with your employee ID. They can reset it for you immediately.

**REMEMBER: KEEP IT SHORT, DIRECT, AND HELPFUL. NO LONG EXPLANATIONS.**"""
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

def create_jwt_token(user_data: dict) -> str:
    """Create a simple JWT-like token for the user"""
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
        role = "admin" if google_user_info["email"].endswith("@gmail.com") else "end_user"
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
    """Handle chat messages, using KB first, then AI fallback."""
    try:
        # Get or create session
        session_id = data.session_id or request.headers.get("Session-ID", f"session_{uuid.uuid4()}")
        session_id = get_or_create_session(session_id)
        
        # Get chat history for this session
        chat_history = get_session_history(session_id)

        # --- Step 1: Search KB for a match ---
        kb_results = search_knowledge_base(data.message)
        if kb_results:
            top = kb_results[0]
            logger.info(f"Knowledge base matched: {top['title']}")
            
            # Save user message and KB response
            save_message_to_history(session_id, "user", data.message, data.user_id)
            save_message_to_history(session_id, "assistant", top["solution"], data.user_id)
            
            return JSONResponse({
                "response": f"✅ {top['title']}\n\n{top['solution']}",
                "category": top["category"],
                "session_id": session_id
            })

        # --- Step 2: No KB match, call AI ---
        ai_response, issue_type = await get_ai_response(data.message, chat_history)
        
        # Validate and clean the AI response
        if not validate_response(ai_response):
            logger.warning("AI response failed validation, using fallback")
            ai_response = "I apologize, but I'm having trouble generating a proper response. Please try rephrasing your question or contact support for immediate assistance."
        else:
            # Clean and format the AI response
            cleaned_response = clean_ai_response(ai_response)
            ai_response = format_ai_response(cleaned_response)
        
        # Save both user message and AI response
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
                "updated_at": row[7],
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

# ----------------------------
# Authentication Endpoints
# ----------------------------
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

@app.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return JSONResponse({
        "user": {
            "id": current_user["user_id"],
            "email": current_user["email"],
            "name": current_user["name"],
            "role": current_user["role"]
        }
    })

# ----------------------------
# User Management Endpoints (Admin Only)
# ----------------------------
@app.get("/users", response_class=JSONResponse)
async def list_users(current_user: dict = Depends(require_admin)):
    """Get all users (admin only)"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, google_id, email, name, picture, role, department, active, created_at, updated_at
            FROM users 
            ORDER BY created_at DESC
        """)
        
        users = []
        for row in cursor.fetchall():
            users.append({
                "id": row[0],
                "google_id": row[1],
                "email": row[2],
                "name": row[3],
                "picture": row[4],
                "role": row[5],
                "department": row[6],
                "active": bool(row[7]),
                "created_at": row[8],
                "updated_at": row[9]
            })
        
        conn.close()
        return JSONResponse({"users": users})
        
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch users")

@app.put("/users/{user_id}", response_class=JSONResponse)
async def update_user(user_id: int, user_data: dict, current_user: dict = Depends(require_admin)):
    """Update user information (admin only)"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")
        
        # Build update query dynamically based on provided fields
        allowed_fields = ["role", "department", "active", "name"]
        update_fields = []
        update_values = []
        
        for field in allowed_fields:
            if field in user_data:
                update_fields.append(f"{field} = ?")
                update_values.append(user_data[field])
        
        if not update_fields:
            conn.close()
            raise HTTPException(status_code=400, detail="No valid fields to update")
        
        update_values.append(user_id)
        query = f"UPDATE users SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        
        cursor.execute(query, update_values)
        conn.commit()
        conn.close()
        
        logger.info(f"User {user_id} updated by admin {current_user['email']}")
        
        return JSONResponse({"message": "User updated successfully"})
        
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update user")

@app.delete("/users/{user_id}", response_class=JSONResponse)
async def deactivate_user(user_id: int, current_user: dict = Depends(require_admin)):
    """Deactivate user (admin only) - soft delete"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="User not found")
        
        # Soft delete - set active to False
        cursor.execute("UPDATE users SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        logger.info(f"User {user_id} deactivated by admin {current_user['email']}")
        
        return JSONResponse({"message": "User deactivated successfully"})
        
    except Exception as e:
        logger.error(f"Error deactivating user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to deactivate user")

# ----------------------------
# Knowledge Base Endpoints
# ----------------------------
@app.get("/knowledge-base", response_class=JSONResponse)
async def list_knowledge_base_public():
    """Return all knowledge base entries (public read access)"""
    kb = get_knowledge_base()
    return {"knowledge_base": kb}

@app.get("/knowledge-base/search", response_class=JSONResponse)
async def search_knowledge_base_public(query: str):
    """Search KB by title, keywords, or solution (public read access)"""
    results = search_knowledge_base(query)
    if not results:
        raise HTTPException(status_code=404, detail="No matching entries found.")
    return results

@app.get("/knowledge-base/{kb_id}", response_class=JSONResponse)
async def get_knowledge_base_entry(kb_id: int):
    """Get specific KB entry (public read access)"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, title, category, solution, keywords, created_at, updated_at
        FROM knowledge_base WHERE id = ?
    """, (kb_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        raise HTTPException(status_code=404, detail="Knowledge base entry not found")
    
    return {
        "id": result[0],
        "title": result[1],
        "category": result[2],
        "solution": result[3],
        "keywords": [kw.strip() for kw in result[4].split(",")] if result[4] else [],
        "created_at": result[5],
        "updated_at": result[6]
    }

@app.post("/knowledge-base", response_class=JSONResponse)
async def add_knowledge_base_entry(entry: dict, current_user: dict = Depends(require_admin)):
    """Add new KB entry (admin only)"""
    required_fields = ["title", "category", "solution"]
    for field in required_fields:
        if field not in entry:
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO knowledge_base (title, category, solution, keywords)
            VALUES (?, ?, ?, ?)
        """, (
            entry["title"],
            entry["category"],
            entry["solution"],
            ",".join(entry.get("keywords", [])) if isinstance(entry.get("keywords"), list)
            else (entry.get("keywords") or "")
        ))
        conn.commit()
        entry_id = cursor.lastrowid
        conn.close()
        
        logger.info(f"KB entry '{entry['title']}' added by admin {current_user['email']}")
        
        return JSONResponse({
            "message": "Knowledge base entry added successfully.",
            "id": entry_id
        })
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Entry with this title already exists")
    except Exception as e:
        conn.close()
        logger.error(f"Error adding KB entry: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add knowledge base entry")

@app.put("/knowledge-base/{kb_id}", response_class=JSONResponse)
async def update_knowledge_base_entry(kb_id: int, entry: dict, current_user: dict = Depends(require_admin)):
    """Update KB entry (admin only)"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM knowledge_base WHERE id = ?", (kb_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Knowledge base entry not found.")

    try:
        cursor.execute("""
            UPDATE knowledge_base
            SET title = ?, category = ?, solution = ?, keywords = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (
            entry.get("title"),
            entry.get("category"),
            entry.get("solution"),
            ",".join(entry.get("keywords", [])) if isinstance(entry.get("keywords"), list)
            else (entry.get("keywords") or ""),
            kb_id
        ))
        conn.commit()
        conn.close()
        
        logger.info(f"KB entry {kb_id} updated by admin {current_user['email']}")
        
        return JSONResponse({"message": f"Knowledge base entry {kb_id} updated successfully."})
    except Exception as e:
        conn.close()
        logger.error(f"Error updating KB entry: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update knowledge base entry")

@app.delete("/knowledge-base/{kb_id}", response_class=JSONResponse)
async def delete_knowledge_base_entry(kb_id: int, current_user: dict = Depends(require_admin)):
    """Delete KB entry (admin only)"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, title FROM knowledge_base WHERE id = ?", (kb_id,))
    result = cursor.fetchone()
    if not result:
        conn.close()
        raise HTTPException(status_code=404, detail="Entry not found.")
    
    cursor.execute("DELETE FROM knowledge_base WHERE id = ?", (kb_id,))
    changes = conn.total_changes
    conn.commit()
    conn.close()
    
    if changes == 0:
        raise HTTPException(status_code=404, detail="Entry not found.")
    
    logger.info(f"KB entry '{result[1]}' (ID: {kb_id}) deleted by admin {current_user['email']}")
    
    return JSONResponse({"message": f"Knowledge base entry {kb_id} deleted successfully."})

# ----------------------------
# Routing Rules Endpoints
# ----------------------------
@app.get("/routing-rules", response_class=JSONResponse)
def list_routing_rules():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, keyword, department FROM routing_rules ORDER BY keyword ASC")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "keyword": r[1], "department": r[2]} for r in rows]

@app.post("/routing-rules", response_class=JSONResponse)
def add_routing_rule(rule: dict):
    required_fields = ["keyword", "department"]
    for field in required_fields:
        if field not in rule:
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO routing_rules (keyword, department)
            VALUES (?, ?)
        """, (rule["keyword"].lower(), rule["department"]))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Rule already exists.")
    finally:
        conn.close()
    return {"message": "Routing rule added successfully."}

@app.delete("/routing-rules/{rule_id}", response_class=JSONResponse)
def delete_routing_rule(rule_id: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM routing_rules WHERE id = ?", (rule_id,))
    changes = conn.total_changes
    conn.commit()
    conn.close()
    if changes == 0:
        raise HTTPException(status_code=404, detail="Rule not found.")
    return {"message": f"Routing rule {rule_id} deleted successfully."}

# ----------------------------
# System Endpoints
# ----------------------------
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