export const mockScans = [
  {
    id: "scan-1",
    filename: "compromised_host_traffic.pcap",
    fileSize: "14.2 MB",
    totalPackets: 1240,
    status: "completed",
    startedAt: "2026-06-12 10:14:22",
    completedAt: "2026-06-12 10:14:35",
    threatCount: 3
  },
  {
    id: "scan-2",
    filename: "nmap_syn_scan.pcapng",
    fileSize: "2.1 MB",
    totalPackets: 5400,
    status: "completed",
    startedAt: "2026-06-12 09:30:10",
    completedAt: "2026-06-12 09:30:18",
    threatCount: 12
  },
  {
    id: "scan-3",
    filename: "db_backup_exfiltration.pcap",
    fileSize: "89.5 MB",
    totalPackets: 92100,
    status: "completed",
    startedAt: "2026-06-11 18:22:00",
    completedAt: "2026-06-11 18:22:45",
    threatCount: 1
  },
  {
    id: "scan-4",
    filename: "clean_web_browsing.pcap",
    fileSize: "4.8 MB",
    totalPackets: 1560,
    status: "completed",
    startedAt: "2026-06-11 14:05:12",
    completedAt: "2026-06-11 14:05:20",
    threatCount: 0
  },
  {
    id: "scan-5",
    filename: "corporate_network_sniff.pcap",
    fileSize: "128.4 MB",
    totalPackets: 145000,
    status: "failed",
    startedAt: "2026-06-10 11:12:00",
    completedAt: "2026-06-10 11:12:15",
    threatCount: 0
  }
];

export const mockDetections = {
  "scan-1": [
    {
      id: "det-1",
      packetIndex: 145,
      md5Hash: "a77d393d861eb34e71b888e7d9a97115",
      ruleName: "Detect_WannaCry_Ransomware_Beacon",
      description: "Detects the distinctive outbound tor connection or command & control handshake hash associated with WannaCry ransomware.",
      author: "PRADEESH L",
      tags: ["ransomware", "wannacry", "c2"],
      severity: "high",
      vtPositives: 58,
      vtTotal: 72,
      rawPayload: "474554202f6d756d626c656675636b736765677564676f7267686568666e6578742e6f726720485454502f312e310d0a486f73743a207777772e697571657266736f6470706d7067686a6c61777766736f756665727766636f6d2e636f6d0d0a0d0a"
    },
    {
      id: "det-2",
      packetIndex: 289,
      md5Hash: "258aaed0820a97f193d6d158508f53ec",
      ruleName: "Detect_Tor_Directory_Authority_Request",
      description: "Detects connection attempts to Tor directory authorities to download consensus lists.",
      author: "PRADEESH L",
      tags: ["tor", "anon", "recon"],
      severity: "medium",
      vtPositives: 4,
      vtTotal: 71,
      rawPayload: "16030100800100007c030357732a5a2680fbeb60e6530ffd79c4966601b1fd4f826521377737a37e8643be4fe49a74bc2668c1f68e756b14258aaed0820a97f193d6d158508f53ec000016002f00350005000a00c00900c01300c01400c00a"
    },
    {
      id: "det-3",
      packetIndex: 912,
      md5Hash: "44b1b326fa901873281772d00ac72928",
      ruleName: "Detect_EternalBlue_SMB_Payload",
      description: "Detects the specific kernel shellcode buffer pattern transmitted over SMBv1 protocol (EternalBlue exploit).",
      author: "PRADEESH L",
      tags: ["exploit", "smb", "eternalblue", "ms17-010"],
      severity: "high",
      vtPositives: 64,
      vtTotal: 73,
      rawPayload: "00000085ff534d4272000000001807c8000000000000000000000000000005ff00000000000100ff02001400080001000000000001000000ffff00005400000044b1b326fa901873281772d00ac729285041594c4f4144"
    }
  ],
  "scan-2": [
    {
      id: "det-4",
      packetIndex: 12,
      md5Hash: "f46bad29a32c8f0b27de63af58f76118",
      ruleName: "Detect_SYN_Flood_Scanner",
      description: "Port scan scanner detection flagging rapid successive SYN frames targeting multiple ports.",
      author: "PRADEESH L",
      tags: ["recon", "portscan"],
      severity: "medium",
      vtPositives: 0,
      vtTotal: 72,
      rawPayload: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    }
  ]
};

export const mockPackets = {
  "scan-1": [
    { index: 1, timestamp: "10:14:22.001", sourceIp: "192.168.1.105", destIp: "192.168.1.1", protocol: "DNS", length: 74, info: "Standard query 0x12a3 A www.google.com", isThreat: false },
    { index: 2, timestamp: "10:14:22.015", sourceIp: "192.168.1.1", destIp: "192.168.1.105", protocol: "DNS", length: 90, info: "Standard query response 0x12a3 A www.google.com A 142.250.190.46", isThreat: false },
    { index: 145, timestamp: "10:14:23.402", sourceIp: "192.168.1.105", destIp: "84.200.69.80", protocol: "HTTP", length: 182, info: "GET /mumblefucksgegudgorgherhfnext.org HTTP/1.1", isThreat: true, rawPayload: "474554202f6d756d626c656675636b736765677564676f7267686568666e6578742e6f726720485454502f312e310d0a486f73743a207777772e697571657266736f6470706d7067686a6c61777766736f756665727766636f6d2e636f6d0d0a0d0a" },
    { index: 200, timestamp: "10:14:25.110", sourceIp: "192.168.1.105", destIp: "142.250.190.46", protocol: "TCP", length: 66, info: "50431 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256", isThreat: false },
    { index: 289, timestamp: "10:14:27.889", sourceIp: "192.168.1.105", destIp: "86.59.21.38", protocol: "TLSv1.2", length: 240, info: "Client Hello", isThreat: true, rawPayload: "16030100800100007c030357732a5a2680fbeb60e6530ffd79c4966601b1fd4f826521377737a37e8643be4fe49a74bc2668c1f68e756b14258aaed0820a97f193d6d158508f53ec000016002f00350005000a00c00900c01300c01400c00a" },
    { index: 912, timestamp: "10:14:32.102", sourceIp: "10.0.0.12", destIp: "10.0.0.25", protocol: "SMB", length: 154, info: "Negotiate Protocol Request", isThreat: true, rawPayload: "00000085ff534d4272000000001807c8000000000000000000000000000005ff00000000000100ff02001400080001000000000001000000ffff00005400000044b1b326fa901873281772d00ac729285041594c4f4144" }
  ]
};
