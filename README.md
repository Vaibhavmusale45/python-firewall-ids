# python-firewall-
# 🔐 Python Firewall & Intrusion Detection System

## 📌 Overview

This project is a **Firewall + Intrusion Detection System (IDS)** built using Python and PyDivert.
It captures real-time network packets, analyzes traffic behavior, detects suspicious activity, and automatically blocks malicious IPs.

---

## 🚀 Features

* 📡 Real-time packet capturing (WinDivert)
* 🧠 Rule-based intrusion detection
* 🚫 Automatic IP blocking system
* 📊 Live traffic monitoring dashboard (Tkinter GUI)
* 📝 Logging system for events
* 💾 Persistent blocked IP storage

---

## 🛠 Technologies Used

* Python
* PyDivert (WinDivert)
* Tkinter (GUI)
* Networking Concepts (TCP/IP)

---

## ⚙️ How It Works

1. Captures packets at network layer
2. Monitors:

   * Packet rate (per IP)
   * Port scanning behavior
3. Detects suspicious activity using rule-based logic
4. Automatically blocks malicious IPs
5. Displays traffic and alerts in GUI

---

## ▶️ How to Run

### 1. Install dependencies

```bash
pip install pydivert
```

### 2. Run as Administrator (IMPORTANT)

```bash
python main.py
```

---

## 📸 Screenshots

<img width="1248" height="847" alt="Screenshot 2026-04-29 000530" src="https://github.com/user-attachments/assets/d7fe6e65-cffe-4059-aff4-54752191848a" />


---

## 📚 What I Learned

* Packet-level network monitoring
* Firewall vs IDS implementation
* Real-time system design
* Handling concurrency (threading + GUI queue)

---

## ⚠️ Note

* Requires **Administrator privileges**
* Works only on **Windows** (uses WinDivert)

---

## 🚀 Future Improvements

* Machine learning-based detection
* Traffic visualization graphs
* Advanced filtering rules
* Performance optimization

---

## 👨‍💻 Author

Vaibhav Musale

---
