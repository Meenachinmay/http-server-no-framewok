package org.meenachinmay

import kotlinx.coroutines.*
import java.io.*
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.CoroutineContext

data class User(val username: String, val passwordHash: String)
data class Session(val id: String, var username: String? = null)

class AuthServer(private val port: Int) : CoroutineScope {
    private val job = Job()
    override val coroutineContext: CoroutineContext
        get() = Dispatchers.Default + job

    private val users = ConcurrentHashMap<String, User>()
    private val sessions = ConcurrentHashMap<String, Session>()

    fun start() = runBlocking {
        println("Starting server on port $port")
        val server = ServerSocket(port)
        while (isActive) {
            val client = withContext(Dispatchers.IO) { server.accept() }
            launch { handleClient(client) }
        }
    }

    private suspend fun handleClient(client: Socket) {
        withContext(Dispatchers.IO) {
            client.use { socket ->
                val reader = BufferedReader(InputStreamReader(socket.inputStream))
                val writer = PrintWriter(socket.outputStream, true)

                val request = parseRequest(reader)
                if (request == null) {
                    sendResponse(writer, "400 Bad Request", "text/plain", "Invalid request")
                    return@withContext
                }

                val sessionId = getSessionIdFromCookie(request.headers["Cookie"])
                val session = getOrCreateSession(sessionId)

                when (request.path) {
                    "/register" -> handleRegister(request, writer)
                    "/login" -> handleLogin(request, session, writer)
                    "/logout" -> handleLogout(session, writer)
                    "/dashboard" -> handleDashboard(session, writer)
                    else -> sendResponse(writer, "404 Not Found", "text/plain", "404 Not Found")
                }
            }
        }
    }

    private suspend fun parseRequest(reader: BufferedReader): Request? = withContext(Dispatchers.IO) {
        try {
            val firstLine = reader.readLine()?.split(" ") ?: return@withContext null
            if (firstLine.size < 3) return@withContext null

            val method = firstLine[0]
            val path = firstLine[1]
            val headers = mutableMapOf<String, String>()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                if (line!!.isEmpty()) break
                val parts = line!!.split(": ", limit = 2)
                if (parts.size == 2) {
                    headers[parts[0]] = parts[1]
                }
            }

            val contentLength = headers["Content-Length"]?.toIntOrNull() ?: 0
            val body = if (contentLength > 0) {
                val buffer = CharArray(contentLength)
                reader.read(buffer)
                String(buffer)
            } else ""

            Request(method, path, headers, body)
        } catch (e: IOException) {
            println("Error parsing request: ${e.message}")
            null
        }
    }

    private fun getSessionIdFromCookie(cookieHeader: String?): String? {
        return cookieHeader?.split("; ")
            ?.find { it.startsWith("sessionId=") }
            ?.substringAfter("sessionId=")
    }

    private fun getOrCreateSession(sessionId: String?): Session {
        if (sessionId != null && sessions.containsKey(sessionId)) {
            return sessions[sessionId]!!
        }
        val newSessionId = UUID.randomUUID().toString()
        val newSession = Session(newSessionId)
        sessions[newSessionId] = newSession
        return newSession
    }

    private suspend fun handleRegister(request: Request, writer: PrintWriter) = withContext(Dispatchers.Default) {
        val params = parseUrlEncodedParams(request.body)
        val username = params["username"]
        val password = params["password"]

        if (username == null || password == null) {
            sendResponse(writer, "400 Bad Request", "text/plain", "Missing username or password")
            return@withContext
        }

        if (users.containsKey(username)) {
            sendResponse(writer, "400 Bad Request", "text/plain", "Username already exists")
            return@withContext
        }

        val passwordHash = hashPassword(password)
        users[username] = User(username, passwordHash)
        sendResponse(writer, "200 OK", "text/plain", "User registered successfully")
    }

    private suspend fun handleLogin(request: Request, session: Session, writer: PrintWriter) = withContext(Dispatchers.Default) {
        val params = parseUrlEncodedParams(request.body)
        val username = params["username"]
        val password = params["password"]

        if (username == null || password == null) {
            sendResponse(writer, "400 Bad Request", "text/plain", "Missing username or password")
            return@withContext
        }

        val user = users[username]
        if (user == null || !verifyPassword(password, user.passwordHash)) {
            sendResponse(writer, "401 Unauthorized", "text/plain", "Invalid username or password")
            return@withContext
        }

        session.username = username
        sendResponse(writer, "200 OK", "text/plain", "Login successful", session.id)
    }

    private suspend fun handleLogout(session: Session, writer: PrintWriter) = withContext(Dispatchers.Default) {
        session.username = null
        sendResponse(writer, "200 OK", "text/plain", "Logout successful", null)
    }

    private suspend fun handleDashboard(session: Session, writer: PrintWriter) = withContext(Dispatchers.Default) {
        if (session.username == null) {
            sendResponse(writer, "401 Unauthorized", "text/plain", "You must be logged in to view this page")
            return@withContext
        }
        sendResponse(writer, "200 OK", "text/plain", "Welcome to your dashboard, ${session.username}!")
    }

    private suspend fun sendResponse(writer: PrintWriter, status: String, contentType: String, body: String, sessionId: String? = null) = withContext(Dispatchers.IO) {
        writer.println("HTTP/1.1 $status")
        writer.println("Content-Type: $contentType")
        writer.println("Content-Length: ${body.length}")
        if (sessionId != null) {
            writer.println("Set-Cookie: sessionId=$sessionId; HttpOnly")
        }
        writer.println()
        writer.print(body)
        writer.flush()
    }

    private fun parseUrlEncodedParams(body: String): Map<String, String> {
        return body.split("&")
            .map { it.split("=") }
            .filter { it.size == 2 }
            .associate { it[0] to it[1] }
    }

    private suspend fun hashPassword(password: String): String = withContext(Dispatchers.Default) {
        val bytes = password.toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        digest.fold("") { str, it -> str + "%02x".format(it) }
    }

    private suspend fun verifyPassword(password: String, hash: String): Boolean = withContext(Dispatchers.Default) {
        hashPassword(password) == hash
    }
}

data class Request(val method: String, val path: String, val headers: Map<String, String>, val body: String)

fun main() = runBlocking {
    val server = AuthServer(8080)
    server.start()
}