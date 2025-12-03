"""FastAPI backend for LLM Council."""

import asyncio
import json
import logging
import os
import uuid
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from pydantic import BaseModel

from . import storage
from .auth import AUTH_STORE, Notifier, RateLimiter
from .council import run_full_council, generate_conversation_title, stage1_collect_responses, stage2_collect_rankings, stage3_synthesize_final, calculate_aggregate_rankings

app = FastAPI(title="LLM Council API")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication helpers
rate_limiter = RateLimiter(max_attempts=5, window_seconds=60, block_seconds=300)
notifier = Notifier(mode=os.getenv("NOTIFIER_MODE", "log"))

# Metrics
LOGIN_ATTEMPTS = Counter("auth_login_attempts_total", "Total login attempts")
LOGIN_SUCCESSES = Counter("auth_login_success_total", "Successful logins")
LOGIN_FAILURES = Counter("auth_login_failure_total", "Failed logins")
LOGIN_THROTTLED = Counter("auth_login_throttled_total", "Throttled login attempts")
PASSWORD_RESET_REQUESTS = Counter(
    "auth_password_reset_requests_total", "Password reset requests"
)
PASSWORD_RESET_SUCCESSES = Counter(
    "auth_password_reset_success_total", "Successful password resets"
)
PASSWORD_RESET_FAILURES = Counter(
    "auth_password_reset_failure_total", "Failed password resets"
)


class CreateConversationRequest(BaseModel):
    """Request to create a new conversation."""
    pass


class LoginRequest(BaseModel):
    """User login request payload."""

    username: str
    password: str


class PasswordResetRequest(BaseModel):
    """Initiate password reset payload."""

    email: str


class PasswordResetConfirmation(BaseModel):
    """Confirm password reset payload."""

    token: str
    new_password: str


class SendMessageRequest(BaseModel):
    """Request to send a message in a conversation."""
    content: str


class ConversationMetadata(BaseModel):
    """Conversation metadata for list view."""
    id: str
    created_at: str
    title: str
    message_count: int


class Conversation(BaseModel):
    """Full conversation with all messages."""
    id: str
    created_at: str
    title: str
    messages: List[Dict[str, Any]]


@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "ok", "service": "LLM Council API"}


@app.post("/api/auth/login")
async def login(request: Request, payload: LoginRequest):
    """Authenticate a user with simple rate limiting."""

    key = f"{request.client.host}:{payload.username}"
    if not rate_limiter.allow(key):
        LOGIN_THROTTLED.inc()
        logger.warning(
            "auth_throttled",
            extra={"username": payload.username, "client_ip": request.client.host},
        )
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please wait before retrying.",
        )

    LOGIN_ATTEMPTS.inc()

    if AUTH_STORE.authenticate(payload.username, payload.password):
        LOGIN_SUCCESSES.inc()
        logger.info(
            "auth_success",
            extra={"username": payload.username, "client_ip": request.client.host},
        )
        return {"status": "ok", "message": "Login successful"}

    LOGIN_FAILURES.inc()
    logger.warning(
        "auth_failure",
        extra={"username": payload.username, "client_ip": request.client.host},
    )
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/auth/password/forgot")
async def request_password_reset(payload: PasswordResetRequest):
    """Issue a one-time password reset token and dispatch via notifier."""

    PASSWORD_RESET_REQUESTS.inc()
    token = AUTH_STORE.create_reset_token(payload.email)
    if token:
        notifier.send_password_reset(payload.email, token)
        logger.info("password_reset_requested", extra={"email": payload.email})
        return {"status": "ok", "message": "If the account exists, a token was sent."}

    PASSWORD_RESET_FAILURES.inc()
    logger.warning("password_reset_request_failed", extra={"email": payload.email})
    return {"status": "ok", "message": "If the account exists, a token was sent."}


@app.post("/api/auth/password/reset")
async def reset_password(payload: PasswordResetConfirmation):
    """Reset the password using a signed, one-time token."""

    username = AUTH_STORE.validate_reset_token(payload.token)
    if not username:
        PASSWORD_RESET_FAILURES.inc()
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    try:
        AUTH_STORE.set_password(username, payload.new_password)
    except ValueError:
        PASSWORD_RESET_FAILURES.inc()
        raise HTTPException(status_code=404, detail="User not found")

    AUTH_STORE.mark_token_used(payload.token)
    PASSWORD_RESET_SUCCESSES.inc()
    logger.info("password_reset_success", extra={"username": username})
    return {"status": "ok", "message": "Password reset successful"}


@app.get("/api/conversations", response_model=List[ConversationMetadata])
async def list_conversations():
    """List all conversations (metadata only)."""
    return storage.list_conversations()


@app.post("/api/conversations", response_model=Conversation)
async def create_conversation(request: CreateConversationRequest):
    """Create a new conversation."""
    conversation_id = str(uuid.uuid4())
    conversation = storage.create_conversation(conversation_id)
    return conversation


@app.get("/api/conversations/{conversation_id}", response_model=Conversation)
async def get_conversation(conversation_id: str):
    """Get a specific conversation with all its messages."""
    conversation = storage.get_conversation(conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation


@app.post("/api/conversations/{conversation_id}/message")
async def send_message(conversation_id: str, request: SendMessageRequest):
    """
    Send a message and run the 3-stage council process.
    Returns the complete response with all stages.
    """
    # Check if conversation exists
    conversation = storage.get_conversation(conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # Check if this is the first message
    is_first_message = len(conversation["messages"]) == 0

    # Add user message
    storage.add_user_message(conversation_id, request.content)

    # If this is the first message, generate a title
    if is_first_message:
        title = await generate_conversation_title(request.content)
        storage.update_conversation_title(conversation_id, title)

    # Run the 3-stage council process
    stage1_results, stage2_results, stage3_result, metadata = await run_full_council(
        request.content
    )

    # Add assistant message with all stages
    storage.add_assistant_message(
        conversation_id,
        stage1_results,
        stage2_results,
        stage3_result
    )

    # Return the complete response with metadata
    return {
        "stage1": stage1_results,
        "stage2": stage2_results,
        "stage3": stage3_result,
        "metadata": metadata
    }


@app.post("/api/conversations/{conversation_id}/message/stream")
async def send_message_stream(conversation_id: str, request: SendMessageRequest):
    """
    Send a message and stream the 3-stage council process.
    Returns Server-Sent Events as each stage completes.
    """
    # Check if conversation exists
    conversation = storage.get_conversation(conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # Check if this is the first message
    is_first_message = len(conversation["messages"]) == 0

    async def event_generator():
        try:
            # Add user message
            storage.add_user_message(conversation_id, request.content)

            # Start title generation in parallel (don't await yet)
            title_task = None
            if is_first_message:
                title_task = asyncio.create_task(generate_conversation_title(request.content))

            # Stage 1: Collect responses
            yield f"data: {json.dumps({'type': 'stage1_start'})}\n\n"
            stage1_results = await stage1_collect_responses(request.content)
            yield f"data: {json.dumps({'type': 'stage1_complete', 'data': stage1_results})}\n\n"

            # Stage 2: Collect rankings
            yield f"data: {json.dumps({'type': 'stage2_start'})}\n\n"
            stage2_results, label_to_model = await stage2_collect_rankings(request.content, stage1_results)
            aggregate_rankings = calculate_aggregate_rankings(stage2_results, label_to_model)
            yield f"data: {json.dumps({'type': 'stage2_complete', 'data': stage2_results, 'metadata': {'label_to_model': label_to_model, 'aggregate_rankings': aggregate_rankings}})}\n\n"

            # Stage 3: Synthesize final answer
            yield f"data: {json.dumps({'type': 'stage3_start'})}\n\n"
            stage3_result = await stage3_synthesize_final(request.content, stage1_results, stage2_results)
            yield f"data: {json.dumps({'type': 'stage3_complete', 'data': stage3_result})}\n\n"

            # Wait for title generation if it was started
            if title_task:
                title = await title_task
                storage.update_conversation_title(conversation_id, title)
                yield f"data: {json.dumps({'type': 'title_complete', 'data': {'title': title}})}\n\n"

            # Save complete assistant message
            storage.add_assistant_message(
                conversation_id,
                stage1_results,
                stage2_results,
                stage3_result
            )

            # Send completion event
            yield f"data: {json.dumps({'type': 'complete'})}\n\n"

        except Exception as e:
            # Send error event
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
