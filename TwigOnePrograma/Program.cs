// See https://aka.ms/new-console-template for more information
//Console.WriteLine("Hello, World!");


using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal class Program
{
    private const int Port = 8484;
    private static readonly string LogFilePath = "twig_received_log.txt";

    private static readonly SemaphoreSlim LogLock = new SemaphoreSlim(1, 1);

    static async Task Main(string[] args)
    {
        var listener = new TcpListener(IPAddress.Any, Port);
        listener.Start();

        Console.WriteLine($"[INFO] Listening for TWIG devices on TCP {Port}...");
        Console.WriteLine($"[INFO] Log file: {Path.GetFullPath(LogFilePath)}");

        while (true)
        {
            TcpClient client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
            _ = HandleClientAsync(client);
        }
    }

    private static async Task HandleClientAsync(TcpClient client)
    {
        string sessionId = Guid.NewGuid().ToString("N");
        string remote = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        string clientIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "unknown";

        Console.WriteLine($"[CONNECTED] {sessionId} {remote}");

        try
        {
            client.NoDelay = true;
            client.ReceiveTimeout = 120_000; // 2 min (evita tasks penduradas)

            using (client)
            using (NetworkStream stream = client.GetStream())
            {
                // ACK logo no connect
                await SendAckAsync(stream, sessionId, reason: "CONNECT", ackPayload: "ACK").ConfigureAwait(false);

                byte[] buffer = new byte[4096];

                // Buffer acumulado em ASCII (porque o protocolo que tens visto é ASCII)
                var acc = new StringBuilder(8192);

                while (true)
                {
                    int bytesRead;
                    try
                    {
                        bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    }
                    catch (IOException ioEx)
                    {
                        // Timeouts ou connection reset vão cair aqui
                        await AppendLogAsync($"[ERROR] {DateTime.Now:O} Session={sessionId} IO: {ioEx}\n").ConfigureAwait(false);
                        Console.WriteLine($"[ERROR] {sessionId} IO: {ioEx.Message}");
                        break;
                    }

                    if (bytesRead <= 0) break;

                    // chunk raw
                    byte[] chunk = new byte[bytesRead];
                    Buffer.BlockCopy(buffer, 0, chunk, 0, bytesRead);

                    string hex = HexUtil.ToHex(chunk);
                    string asciiSafe = HexUtil.ToAsciiSafe(chunk);
                    string ascii = Encoding.ASCII.GetString(chunk);

                    // Log chunk
                    await AppendLogAsync($"\n--- {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} ---\n" +
                                         $"Session: {sessionId}\nRemote: {remote}\nIP: {clientIp}\n" +
                                         $"RX CHUNK ({bytesRead} bytes)\nHEX : {hex}\nASCII: {asciiSafe}\n").ConfigureAwait(false);

                    Console.WriteLine($"[RX] {sessionId} {bytesRead} bytes");
                    Console.WriteLine($"     HEX  : {hex}");
                    Console.WriteLine($"     ASCII: {asciiSafe}");

                    // acumula para framing
                    acc.Append(ascii);

                    // extrai mensagens completas por delimitador ",nnn"
                    while (TryExtractMessageByNnn(acc, out string rawMessage))
                    {
                        rawMessage = rawMessage.Trim('\r', '\n', ' ');

                        if (string.IsNullOrWhiteSpace(rawMessage))
                            continue;

                        // Parse top-level (sem estragar INF)
                        var msg = TwigMessageParser.ParseTopLevel(rawMessage);

                        // Mostrar + log
                        PrintMessage(sessionId, msg);
                        await AppendLogAsync($"[PARSED] {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} Session={sessionId}\n" +
                                             $"{msg.ToMultilineString()}\n").ConfigureAwait(false);

                        // ACK por mensagem completa
                        await SendAckAsync(stream, sessionId, reason: "EVENT", ackPayload: "ACK").ConfigureAwait(false);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] {sessionId}: {ex.Message}");
            await AppendLogAsync($"[ERROR] {DateTime.Now:O} Session={sessionId}: {ex}\n").ConfigureAwait(false);
        }
        finally
        {
            Console.WriteLine($"[DISCONNECTED] {DateTime.Now:O} {sessionId} {remote}");
            await AppendLogAsync($"[DISCONNECTED] {DateTime.Now:O} Session={sessionId} Remote={remote}\n").ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Extrai mensagens completas usando ",nnn" como terminador.
    /// Mantém o terminador no output (opcional), mas aqui devolvemos sem o extra após.
    /// </summary>
    private static bool TryExtractMessageByNnn(StringBuilder acc, out string message)
    {
        // procura o token ",nnn"
        const string terminator = ",nnn";
        int idx = IndexOf(acc, terminator);
        if (idx < 0)
        {
            message = null;
            return false;
        }

        // mensagem completa inclui até ao fim do terminator
        int end = idx + terminator.Length;
        message = acc.ToString(0, end);

        // remove do acumulador (pode haver mais dados a seguir)
        acc.Remove(0, end);
        return true;
    }

    private static int IndexOf(StringBuilder sb, string value)
    {
        // busca simples (suficiente para este caso)
        for (int i = 0; i <= sb.Length - value.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < value.Length; j++)
            {
                if (sb[i + j] != value[j]) { ok = false; break; }
            }
            if (ok) return i;
        }
        return -1;
    }

    private static void PrintMessage(string sessionId, TwigMessage msg)
    {
        Console.WriteLine($"[MSG] {sessionId} Type={msg.Type} Code={msg.Code} Model={msg.Model} DeviceId={msg.DeviceId}");

        if (msg.PayloadKind == TwigPayloadKind.None)
        {
            Console.WriteLine($"      Payload: (none) [{msg.PayloadRaw}]");
            return;
        }

        if (msg.PayloadKind == TwigPayloadKind.Inf && msg.Inf != null)
        {
            Console.WriteLine($"      INF: mode={msg.Inf.Mode} battery={msg.Inf.BatteryPct}% gpsFix={msg.Inf.GpsFix}");
            Console.WriteLine($"      POS: lat={msg.Inf.Latitude} lon={msg.Inf.Longitude} speed={msg.Inf.SpeedKmh} course={msg.Inf.CourseDeg}");
            Console.WriteLine($"      EVT: \"{msg.Inf.EventText}\" qual={msg.Inf.QualityOrSat} eventTime={msg.Inf.EventTime} txTime={msg.Inf.TxTime}");
        }
        else
        {
            Console.WriteLine($"      PayloadRaw: {msg.PayloadRaw}");
        }
    }

    private static async Task SendAckAsync(NetworkStream stream, string sessionId, string reason, string ackPayload)
    {
        // Mantém CRLF: mesmo que o TWIG não envie \n, costuma aceitar e ajuda debugging
        byte[] bytes = Encoding.ASCII.GetBytes(ackPayload + "\r\n");
        await stream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
        await stream.FlushAsync().ConfigureAwait(false);

        Console.WriteLine($"[TX] {sessionId} ACK ({reason}): {ackPayload}");
        await AppendLogAsync($"[TX] {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} Session={sessionId} ACK({reason})={ackPayload}\n").ConfigureAwait(false);
    }

    private static async Task AppendLogAsync(string text)
    {
        await LogLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(LogFilePath, text).ConfigureAwait(false);
        }
        finally
        {
            LogLock.Release();
        }
    }
}

internal static class HexUtil
{
    public static string ToHex(byte[] data) => BitConverter.ToString(data);

    public static string ToAsciiSafe(byte[] data)
    {
        var sb = new StringBuilder(data.Length);
        foreach (byte b in data)
        {
            char c = (char)b;
            if (c == '\r') sb.Append("\\r");
            else if (c == '\n') sb.Append("\\n");
            else if (c >= 32 && c <= 126) sb.Append(c);
            else sb.Append('.');
        }
        return sb.ToString();
    }
}

internal enum TwigPayloadKind
{
    None,
    Inf,
    Unknown
}

internal sealed class TwigMessage
{
    public string Raw { get; }
    public string Type { get; }
    public string Code { get; }
    public string Model { get; }
    public string DeviceId { get; }

    public TwigPayloadKind PayloadKind { get; }
    public string PayloadRaw { get; }
    public TwigInfPayload Inf { get; }

    public string Tail1 { get; }   // ex: 0011
    public string Tail2 { get; }   // ex: nnn

    public TwigMessage(
        string raw, string type, string code, string model, string deviceId,
        TwigPayloadKind payloadKind, string payloadRaw, TwigInfPayload inf,
        string tail1, string tail2)
    {
        Raw = raw;
        Type = type;
        Code = code;
        Model = model;
        DeviceId = deviceId;
        PayloadKind = payloadKind;
        PayloadRaw = payloadRaw;
        Inf = inf;
        Tail1 = tail1;
        Tail2 = tail2;
    }

    public string ToMultilineString()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"RAW: {Raw}");
        sb.AppendLine($"Type: {Type}");
        sb.AppendLine($"Code: {Code}");
        sb.AppendLine($"Model: {Model}");
        sb.AppendLine($"DeviceId: {DeviceId}");
        sb.AppendLine($"Tail: {Tail1},{Tail2}");
        sb.AppendLine($"PayloadKind: {PayloadKind}");
        sb.AppendLine($"PayloadRaw: {PayloadRaw}");

        if (Inf != null)
        {
            sb.AppendLine("INF:");
            sb.AppendLine($"  Mode: {Inf.Mode}");
            sb.AppendLine($"  BatteryPct: {Inf.BatteryPct}");
            sb.AppendLine($"  GpsFix: {Inf.GpsFix}");
            sb.AppendLine($"  Latitude: {Inf.Latitude}");
            sb.AppendLine($"  Longitude: {Inf.Longitude}");
            sb.AppendLine($"  SpeedKmh: {Inf.SpeedKmh}");
            sb.AppendLine($"  CourseDeg: {Inf.CourseDeg}");
            sb.AppendLine($"  QualityOrSat: {Inf.QualityOrSat}");
            sb.AppendLine($"  EventText: {Inf.EventText}");
            sb.AppendLine($"  EventTime: {Inf.EventTime}");
            sb.AppendLine($"  TxTime: {Inf.TxTime}");
        }

        return sb.ToString();
    }
}

internal sealed class TwigInfPayload
{
    public string Mode { get; set; }
    public int? BatteryPct { get; set; }
    public bool? GpsFix { get; set; }

    public double? Latitude { get; set; }
    public double? Longitude { get; set; }

    public int? SpeedKmh { get; set; }
    public int? CourseDeg { get; set; }
    public int? QualityOrSat { get; set; }

    public string EventText { get; set; }

    public DateTime? EventTime { get; set; }
    public DateTime? TxTime { get; set; }
}

internal static class TwigMessageParser
{
    /// <summary>
    /// Parse top-level sem estragar o payload INF que contém vírgulas internas.
    /// Formatos:
    ///   BENR,0000,TWIG1,85396826,##,0011,nnn
    ///   BENR,0000,TWIG1,85396826,#!INF_...#,0011,nnn
    /// </summary>
    public static TwigMessage ParseTopLevel(string raw)
    {
        // Para garantir robustez: encontra os 4 primeiros campos pelo índice das vírgulas
        // e depois apanha os 2 últimos (tail) a partir do fim.
        string trimmed = raw.Trim();

        // remove terminador ",nnn" para facilitar parsing do tail
        // mas preservamos tail2=nnn
        if (trimmed.EndsWith(",nnn", StringComparison.Ordinal))
            trimmed = trimmed.Substring(0, trimmed.Length - 4); // remove ",nnn"

        // Agora o formato esperado é:
        // Type,Code,Model,DeviceId,Payload,Tail1
        // (Tail2 é sempre nnn)
        // Mas o Payload pode conter vírgulas. Logo:
        // - vamos buscar os 4 primeiros campos por vírgulas
        // - Tail1 é o último campo depois da última vírgula
        // - Payload é o que sobra no meio
        int c1 = trimmed.IndexOf(',');
        int c2 = c1 < 0 ? -1 : trimmed.IndexOf(',', c1 + 1);
        int c3 = c2 < 0 ? -1 : trimmed.IndexOf(',', c2 + 1);
        int c4 = c3 < 0 ? -1 : trimmed.IndexOf(',', c3 + 1);

        if (c4 < 0)
        {
            // fallback: não tem o formato esperado
            return new TwigMessage(raw, "?", "?", "?", "?", TwigPayloadKind.Unknown, trimmed, null, "?", "nnn");
        }

        string type = trimmed.Substring(0, c1);
        string code = trimmed.Substring(c1 + 1, c2 - (c1 + 1));
        string model = trimmed.Substring(c2 + 1, c3 - (c2 + 1));
        string deviceId = trimmed.Substring(c3 + 1, c4 - (c3 + 1));

        // Tail1 = último campo após última vírgula
        int lastComma = trimmed.LastIndexOf(',');
        string tail1 = (lastComma > c4) ? trimmed.Substring(lastComma + 1) : "?";

        // Payload = entre c4+1 e lastComma-1
        string payload = (lastComma > c4) ? trimmed.Substring(c4 + 1, lastComma - (c4 + 1)) : "";

        // Tail2 fixo
        string tail2 = "nnn";

        // Interpreta payload
        TwigPayloadKind kind;
        TwigInfPayload inf = null;

        if (payload == "##")
        {
            kind = TwigPayloadKind.None;
        }
        else if (payload.StartsWith("#!INF_", StringComparison.Ordinal) && payload.EndsWith("#", StringComparison.Ordinal))
        {
            kind = TwigPayloadKind.Inf;
            inf = ParseInf(payload);
        }
        else
        {
            kind = TwigPayloadKind.Unknown;
        }

        return new TwigMessage(raw, type, code, model, deviceId, kind, payload, inf, tail1, tail2);
    }

    private static TwigInfPayload ParseInf(string payload)
    {
        // payload vem como: #!INF_....#
        string core = payload;

        // remove prefixo "#!" e sufixo "#"
        if (core.StartsWith("#!", StringComparison.Ordinal)) core = core.Substring(2);
        if (core.EndsWith("#", StringComparison.Ordinal)) core = core.Substring(0, core.Length - 1);

        // Agora começa por "INF_"
        // tokens por "_" mas lat/lon têm vírgula decimal (ex: N40.38.13,1)
        // Exemplo:
        // INF_01/01_norm_100%_gps_1_N40.38.13,1_W008.38.07,0_19.02.2026_17:38:59_000km/h_278deg_025_Mandown prealarm 2_20.02.2026_12:58:54

        string[] tokens = core.Split('_');
        var inf = new TwigInfPayload();

        // defensivo: valida mínimo
        // índices esperados:
        // 0 INF
        // 1 01/01
        // 2 norm
        // 3 100%
        // 4 gps
        // 5 1
        // 6 N40.38.13,1
        // 7 W008.38.07,0
        // 8 dd.MM.yyyy
        // 9 HH:mm:ss
        // 10 000km/h
        // 11 278deg
        // 12 025
        // 13 EventText (pode ter espaços, mas não underscores)
        // 14 dd.MM.yyyy
        // 15 HH:mm:ss

        if (tokens.Length >= 3) inf.Mode = tokens[2];

        if (tokens.Length >= 4)
        {
            if (TryParseBattery(tokens[3], out int b)) inf.BatteryPct = b;
        }

        if (tokens.Length >= 6)
        {
            // gps fix token "1" / "0"
            inf.GpsFix = tokens[5] == "1";
        }

        if (tokens.Length >= 8)
        {
            inf.Latitude = TryParseLatLon(tokens[6], isLat: true);
            inf.Longitude = TryParseLatLon(tokens[7], isLat: false);
        }

        if (tokens.Length >= 11)
        {
            inf.SpeedKmh = TryParseSpeed(tokens[10]);
        }

        if (tokens.Length >= 12)
        {
            inf.CourseDeg = TryParseIntSuffix(tokens[11], "deg");
        }

        if (tokens.Length >= 13)
        {
            if (int.TryParse(tokens[12], NumberStyles.Integer, CultureInfo.InvariantCulture, out int q))
                inf.QualityOrSat = q;
        }

        if (tokens.Length >= 14)
        {
            inf.EventText = tokens[13];
        }

        if (tokens.Length >= 10)
        {
            inf.EventTime = TryParsePtDateTime(tokens, dateIndex: 8, timeIndex: 9);
        }

        if (tokens.Length >= 16)
        {
            inf.TxTime = TryParsePtDateTime(tokens, dateIndex: 14, timeIndex: 15);
        }

        return inf;
    }

    private static bool TryParseBattery(string token, out int pct)
    {
        pct = 0;
        if (token.EndsWith("%", StringComparison.Ordinal))
            token = token.Substring(0, token.Length - 1);

        return int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out pct);
    }

    private static double? TryParseLatLon(string token, bool isLat)
    {
        // token ex: N40.38.13,1  ou W008.38.07,0
        if (string.IsNullOrEmpty(token) || token.Length < 2) return null;

        char hemi = token[0];
        string rest = token.Substring(1);

        // troca vírgula por ponto para double
        rest = rest.Replace(',', '.');

        if (!double.TryParse(rest, NumberStyles.Float, CultureInfo.InvariantCulture, out double val))
            return null;

        // N/E positivos, S/W negativos
        if (hemi == 'S' || hemi == 'W') val = -val;

        // sanity
        if (isLat && (val < -90 || val > 90)) return null;
        if (!isLat && (val < -180 || val > 180)) return null;

        return val;
    }

    private static int? TryParseSpeed(string token)
    {
        // "000km/h"
        if (string.IsNullOrEmpty(token)) return null;
        if (token.EndsWith("km/h", StringComparison.Ordinal))
            token = token.Substring(0, token.Length - 4);

        if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v))
            return v;

        return null;
    }

    private static int? TryParseIntSuffix(string token, string suffix)
    {
        if (string.IsNullOrEmpty(token)) return null;
        if (token.EndsWith(suffix, StringComparison.Ordinal))
            token = token.Substring(0, token.Length - suffix.Length);

        if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v))
            return v;

        return null;
    }

    private static DateTime? TryParsePtDateTime(string[] tokens, int dateIndex, int timeIndex)
    {
        if (dateIndex >= tokens.Length || timeIndex >= tokens.Length) return null;

        string dt = tokens[dateIndex] + " " + tokens[timeIndex];
        if (DateTime.TryParseExact(dt, "dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture,
                                   DateTimeStyles.AssumeLocal, out DateTime parsed))
            return parsed;

        return null;
    }
}