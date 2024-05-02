# THM: Warzone 2

In this free sequel CTF of Warzone 1 we will be tasked again with investigation of potentially malicious traffic. Navigate to the room [here](https://tryhackme.com/r/room/warzonetwo).

### What was the alert signature for A Network Trojan was Detected?

Open the .pcap in **Brim** since it has signature matching. Navigate to the **Suricata** Alerts by Category

![Untitled](THM%20Warzone%202%20b0412579a6324471b163b3fc5e41129f/Untitled.png)

We can see the Trojan category matched some traffic, lets use it as standalone filter and inspect the result.

![Untitled](THM%20Warzone%202%20b0412579a6324471b163b3fc5e41129f/Untitled%201.png)

**Answer:** ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2

### What was the alert signature for Potential Corporate Privacy Violation?

Known drill.

**Answer:** ET POLICY PE EXE or DLL Windows file download HTTP

### What was the IP to trigger either alert? Enter your answer in a defanged format.

Since we have only single alert, answer is pretty straight forward. For correct answer use [CyberChef](https://cyberchef.org/) defang IP address.

**Answer:** 185[.]118[.]164[.]8

### Provide the full URI for the malicious downloaded file. In your answer, defang the URI.

Using `path=”http” | id.resp_h=185.118.164.8` query to filter all HTTP traffic associated with the malicious IP, we can spot our URI pretty easily. For correct answer use [CyberChef](https://cyberchef.org/) defang URI.

**Answer:** http://awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab

### What is the name of the payload within the cab file?

To get this answer we need to check the file HASH - navigate to the **File Activity** in **Brim**. As we can see we have single file and couple of columns, navigate to your right to get the **MD5** or **SHA1** hash.

![Untitled](THM%20Warzone%202%20b0412579a6324471b163b3fc5e41129f/Untitled%202.png)

![Untitled](THM%20Warzone%202%20b0412579a6324471b163b3fc5e41129f/Untitled%203.png)

A hash function is a mathematical algorithm that takes an input (or "message") and returns a fixed-size string of bytes. The output, typically a "hash code" or "digest", uniquely represents the data fed into the hash function. Hash is fixed, one way it means same data will still have the same hash value - hash is very useful to preserve state of data or check an integrity of data or file. Now, since we have an SHA1 hash lets check for any alerts in [Virus Total](https://www.virustotal.com/gui/home/upload).

![Untitled](THM%20Warzone%202%20b0412579a6324471b163b3fc5e41129f/Untitled%204.png)

Pretty nasty, navigate to **Details** to get our answer.

**Answer:** draw.dll

### What is the user-agent associated with this network traffic?

Filter for HTTP traffic associated with previously discovered address with query `path=”http” | id.resp_h=185.118.164.8` and check for HTTP details.

![Untitled](THM%20Warzone%202%20b0412579a6324471b163b3fc5e41129f/Untitled%205.png)

**Answer:** Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)

### What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? Enter the domains defanged and in alphabetical order.

Hint will guide us - lets check the **Suricata Alerts by Category** again and see **Misc activity**. From there we will check DNS traffic and filter for IP address.

**Answer:** a-zcorner[.]com,knockoutlights[.]com

### There are IP addresses flagged as Not Suspicious Traffic. What are the IP addresses? Enter your answer in numerical order and defanged.

Navigating to **Suricata Alerts by Category**, we can see there is category with this name. 

![Untitled](THM%20Warzone%202%20b0412579a6324471b163b3fc5e41129f/Untitled%206.png)

Use **Not Suspicious Traffic** as standalone filter and check for answers. For correct answer use [CyberChef](https://cyberchef.org/) defang both IP addresses.

**Answer:** 142[.]93[.]211[.]176,64[.]225[.]65[.]166

### For the first IP address flagged as Not Suspicious Traffic. According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format.

Again lets open the **Suricata Alerts by Category** and filter for **Not Suspicious Traffic**. Examine the first IP address in order. You can use **Brim** or **Wireshark** to pair DNS queries with that IP address. For correct answer use [CyberChef](https://cyberchef.org/) to defang URL.

**Answer:** safebanktest[.]top,tocsicambar[.]xyz,ulcertification[.]xyz

### Now for the second IP marked as Not Suspicious Traffic. What was the domain you spotted in the network traffic associated with this IP address? Enter your answer in a defanged format.

Same drill, there is only one left. For correct answer use [CyberChef](https://cyberchef.org/) to defang URL.

**Answer:** 2partscow[.]top

Easy, stay safe.