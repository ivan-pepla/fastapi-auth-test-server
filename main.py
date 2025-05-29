# main.py - Simple FastAPI server to test Basic Authentication, Pre-shared Key Authentication & OAuth2 Authentication
# OAuth2 Authentication assumes machine-to-machine authentication (client credentials flow)

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, Any
import base64
import secrets
import jwt
from datetime import datetime, timedelta
import uvicorn

app = FastAPI(title="Authentication Test API")

# Test credentials for Basic Auth
BASIC_USERNAME = "testuser"
BASIC_PASSWORD = "testpass123"

# Test pre-shared key
VALID_API_KEY = "test-api-key-12345"
API_KEY_HEADER = "X-API-KEY"

# OAuth2/JWT settings for testing
JWT_SECRET = "test-jwt-secret-key-for-testing-only"
JWT_ALGORITHM = "HS256"

# Security schemes
security_basic = HTTPBasic()
security_bearer = HTTPBearer()

class TestResponse(BaseModel):
    message: str
    auth_method: str
    user_info: Optional[Dict[str, Any]] = None
    request_data: Optional[Dict[str, Any]] = None

class TestRequest(BaseModel):
    name: str
    data: Optional[Dict[str, Any]] = None

# Helper functions
def verify_basic_auth(credentials: HTTPBasicCredentials = Depends(security_basic)):
    """Verify basic authentication credentials."""
    is_correct_username = secrets.compare_digest(credentials.username, BASIC_USERNAME)
    is_correct_password = secrets.compare_digest(credentials.password, BASIC_PASSWORD)
    
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def verify_api_key(api_key: Optional[str] = Header(None, alias=API_KEY_HEADER)):
    """Verify pre-shared key authentication."""
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail=f"Missing {API_KEY_HEADER} header"
        )
    
    if not secrets.compare_digest(api_key, VALID_API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return api_key

def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    """Verify JWT token authentication."""
    try:
        payload = jwt.decode(
            credentials.credentials, 
            JWT_SECRET, 
            algorithms=[JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

# Test endpoints for each authentication method

@app.post("/test/basic-auth", response_model=TestResponse)
async def test_basic_auth(
    request_data: TestRequest,
    username: str = Depends(verify_basic_auth)
):
    """Test endpoint for Basic Authentication."""
    return TestResponse(
        message="Basic authentication successful!",
        auth_method="Basic Authentication",
        user_info={"username": username},
        request_data=request_data.dict()
    )

@app.post("/test/api-key", response_model=TestResponse)
async def test_api_key_auth(
    request_data: TestRequest,
    api_key: str = Depends(verify_api_key)
):
    """Test endpoint for Pre-shared Key Authentication."""
    return TestResponse(
        message="API key authentication successful!",
        auth_method="Pre-shared Key Authentication",
        user_info={"api_key": api_key[:10] + "..."},  # Partial key for security
        request_data=request_data.dict()
    )

@app.post("/test/oauth2", response_model=TestResponse)
async def test_oauth2_auth(
    request_data: TestRequest,
    token_payload: Dict[str, Any] = Depends(verify_jwt_token)
):
    """Test endpoint for OAuth2/JWT Authentication."""
    return TestResponse(
        message="OAuth2 authentication successful!",
        auth_method="OAuth2/JWT Authentication",
        user_info=token_payload,
        request_data=request_data.dict()
    )

# Helper endpoint to generate test JWT tokens
@app.post("/auth/token")
async def generate_test_token(client_id: str = "test_client", scope: str = "read write"):
    """Generate a test JWT token for OAuth2 testing."""
    payload = {
        "sub": client_id,
        "scope": scope,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iss": "test-auth-server",
        "aud": "test-audience"
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": scope
    }

# OAuth2 token endpoint (Client Credentials flow simulation)
@app.post("/oauth/token")
async def oauth_token_endpoint(request: Request):
    """Simulate OAuth2 token endpoint for client credentials flow."""
    form_data = await request.form()
    
    # Validate client credentials
    client_id = form_data.get("client_id")
    client_secret = form_data.get("client_secret")
    grant_type = form_data.get("grant_type")
    
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=400,
            detail="unsupported_grant_type"
        )
    
    # Simple validation (in real implementation, check against database)
    if client_id != "test_client_id" or client_secret != "test_client_secret":
        raise HTTPException(
            status_code=401,
            detail="invalid_client"
        )
    
    # Generate token
    payload = {
        "sub": client_id,
        "scope": form_data.get("scope", "read write"),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iss": "test-auth-server",
        "aud": "test-audience"
    }
    
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": payload["scope"]
    }

@app.get("/")
async def root():
    """Root endpoint with testing instructions."""
    return {
        "message": "Authentication Test API",
        "endpoints": {
            "basic_auth": "/test/basic-auth (username: testuser, password: testpass123)",
            "api_key": "/test/api-key (X-API-KEY: test-api-key-12345)",
            "oauth2": "/test/oauth2 (get token from /oauth/token first)",
            "token_generator": "/auth/token (helper to generate JWT tokens)",
            "oauth_endpoint": "/oauth/token (OAuth2 client credentials flow)"
        },
        "test_credentials": {
            "basic_auth": {"username": BASIC_USERNAME, "password": BASIC_PASSWORD},
            "api_key": VALID_API_KEY,
            "oauth2": {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "token_endpoint": "http://localhost:10000/oauth/token"
            }
        }
    }

if __name__ == "__main__":
    print("Starting Authentication Test API...")
    print("Basic Auth - Username: testuser, Password: testpass123")
    print("API Key - X-API-KEY: test-api-key-12345")
    print("OAuth2 - Client ID: test_client_id, Client Secret: test_client_secret")
    uvicorn.run(app, host="0.0.0.0", port=10000)