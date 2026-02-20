This project implements a robust asynchronous TCP server in C# (.NET) designed to receive, acknowledge, log, and parse real-time messages from TWIG personal safety devices.
The system was built with a strong focus on:
- Network reliability
- Protocol-level message framing
- Secure logging practices
- Defensive parsing
- Concurrency control
- Production-ready async architecture

It supports structured parsing of TWIG INF payloads, including GPS coordinates, battery status, device mode, timestamps, speed, course, and event information.

🚀 Key Features

✅ Asynchronous TCP Server

- Built using TcpListener
- Fully async (async/await)
- Handles multiple concurrent client sessions
- Non-blocking architecture

✅ Message Framing Engine

- Custom framing logic based on TWIG terminator ,nnn
- Handles partial TCP packet reads
- Accumulates fragmented payloads safely

✅ Protocol Parsing Engine

Top-level parser that:

- Preserves payload integrity
- Avoids breaking INF payloads containing internal commas
- Structured domain model (TwigMessage, TwigInfPayload)

Defensive validation & error handling

✅ INF Payload Deep Parsing

Parses:
- Device mode
- Battery percentage
- GPS fix status
- Latitude & Longitude (with hemisphere detection)
- Speed (km/h)
- Course (degrees)
- Signal quality / satellites
- Event text
- Event time
- Transmission time

✅ Thread-Safe Logging

- Uses SemaphoreSlim to prevent race conditions
- Hex + ASCII safe logging
- Session-based structured logs
- Timestamp precision (milliseconds)

✅ Automatic ACK Handling

Sends ACK on:

- Connection established
- Each fully parsed event
- Configurable ACK payload

🧠 Technical Architecture

- Device connects
- Server sends ACK
- Server reads TCP stream
- Accumulates raw data
- Extracts complete messages via ,nnn
- Parses message
- Logs structured output
- Sends ACK per event
- Handles disconnect cleanly

📡 Example Incoming Message

BENR,0000,TWIG1,85396826,#!INF_01/01_norm_100%_gps_1_N40.38.13,1_W008.38.07,0_19.02.2026_17:38:59_000km/h_278deg_025_Mandown prealarm 2_20.02.2026_12:58:54#,0011,nnn

Parsed Output:

Type: BENR
Code: 0000
Model: TWIG1
DeviceId: 85396826
Mode: norm
BatteryPct: 100
GpsFix: true
Latitude: 40.38...
Longitude: -8.38...
SpeedKmh: 0
CourseDeg: 278
EventText: Mandown prealarm 2
EventTime: 19.02.2026 17:38:59
TxTime: 20.02.2026 12:58:54

🛡️ Defensive Engineering
This project demonstrates:

- Proper TCP stream handling
- Protection against partial reads
- Timeout handling
- IO exception management
- Safe concurrent file writing
- Input sanitization
- Culture-invariant numeric parsing
- Safe ASCII handling for binary safety

⚙️ Technologies Used

- C#
- .NET
- TCP/IP Networking
- Asynchronous Programming
- Protocol Engineering
- Structured Logging

🎯 Why This Project Matters

This project demonstrates real-world capabilities in:
- Network protocol reverse engineering
- Cybersecurity monitoring foundations
- Embedded device communication
- Low-level TCP server design
- Defensive parsing techniques

It is highly relevant for roles in:
- Cybersecurity
- Network Engineering
- Backend Development
- SOC Engineering
- IoT Infrastructure
- Secure Systems Development

🔎 Skills Demonstrated

- TCP protocol handling
- Async concurrency patterns
- Custom message framing logic
- Structured domain modeling
- Thread-safe logging
- GPS coordinate normalization
- Culture-safe parsing
- Error handling strategy
- Production-grade coding standards

📈 Potential Improvements

- TLS encryption support
- Structured JSON logging
- Database persistence layer
- REST API for monitoring
- Protocol fuzz testing

👨‍💻 Author

Gonçalo Cabral
CTeSP in Informatics & Organizational Communication
Focused on Cybersecurity, Networking & Secure Systems Development
