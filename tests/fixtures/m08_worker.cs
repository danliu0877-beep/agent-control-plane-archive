using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

// Fixed synthetic adversary. Exit codes are collected by the host, not LLM claims.
public class M08Worker {
    public static int Main(string[] args) {
        try {
            switch(args[0]) {
                case "read": File.ReadAllText(args[1]); return 0;
                case "write": File.AppendAllText(args[1], "M08-WRITE\n"); return 0;
                case "env": return Environment.GetEnvironmentVariable("M08_SECRET_CANARY") == null ? 0 : 92;
                case "tcp":
                    using(var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)) {
                        var result=socket.BeginConnect(IPAddress.Parse(args[1]),int.Parse(args[2]),null,null);
                        if(!result.AsyncWaitHandle.WaitOne(3000)) return 93;
                        socket.EndConnect(result); return 0;
                    }
                case "udp":
                    using(var socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp)) {
                        socket.SendTo(new byte[]{77,48,56},new IPEndPoint(IPAddress.Parse(args[1]),int.Parse(args[2]))); return 0;
                    }
                case "hold":
                    using(var stream=new FileStream(args[1],FileMode.Append,FileAccess.Write,FileShare.ReadWrite)) {
                        while(true) { stream.WriteByte(65); stream.Flush(); Thread.Sleep(100); }
                    }
                default: return 94;
            }
        } catch(SocketException e) { return e.ErrorCode; }
          catch(UnauthorizedAccessException) { return 5; }
          catch(IOException e) { return e.HResult & 65535; }
          catch(Exception) { return 95; }
    }
}
