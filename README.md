# LFI-SSH-Fuzzer
This program Prompts you for the Local File Inclusion information and will automatically search the /etc/passwd. Extract the Users and  will search for and download any SSH key or variation of keys to the local computer. This program also performs the CVE-2021-41773_ apache2.4.49 and 50 transversal path exploit.
use -help or -h in the main program for all information on how to use.



Legal & Ethical Use
⚠️ IMPORTANT: This tool is for authorized security testing only.

Use only on systems you own or have explicit written permission to test

Comply with all applicable laws and regulations

Respect privacy and data protection requirements

Use responsibly and ethically

The author assumes no liability for misuse of this tool.

Troubleshooting
Common Issues
Connection errors: Check network connectivity and firewall rules

SSL errors: Use http instead of https or adjust SSL settings

Encoding issues: Try different encoding methods

Rate limiting: Increase --rate value or add delays

Debug Mode
Enable verbose output during interactive prompts or add --verbose flag.
