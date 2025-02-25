################################################################################
#
# file:     README
#
# @Author:   Athanasios Ioannis Xanthopoulos && Filippos Fouskas
# @Version:  25/01/2025
# @email:    csd4702@csd.uoc.gr && csd5032@csd.uoc.gr
#
# README
#
#################################################################################


########################  HY458 - Cryptography - Project  ########################

Για την εκτέλεση του προγράμματος μας πρέπει να είναι προεγκατεστημένες
οι εξής βιβλιοθήκες:
    i) PyQt5
    ii) pycryptodome

Για την άμεση εγκατάσταση τους, μπορείτε να χρησιμοποιήσετε την εντολή:
    "pip install -r requirements.txt"

Στον φάκελο υπάρχουν τα εξής python αρχεία:

1) e-shop.py: Είναι ένα απλό e-shop που δημιουργήθηκε για σκοπούς testing.
Σε αυτό χρησιμοποιούνται συναρτήσεις από κρυπτογραφικούς αλγορίθμους οι
οποίοι ΔΕΝ είναι quantum safe, όπως οι εξής:
    i) AES 128bit
    ii) RSA 2048bit
    iii) MD5 hash

2) risk_assessment_tool.py: Είναι το inventory tool που ζητείται από την
δεύτερη φάση του project. Για να τρέξει χρησιμοποιήστε το εξής command:
    "python3 risk_assessment_tool.py"

-INPUT: Φάκελος που θέλουμε να κάνουμε assess για post-quantum vulnerable
    cryptographic αλγορίθμους.

-OUTPUT: Δύο αρχεία:
    i) scan_result.txt
    ii) scan_result.json
    Αυτά τα αρχεία περιέχουν προγράμματα και γραμμές κώδικα στα αντίστοιχα
    προγράμματα, όπου βρέθηκαν vulnerable αλγόριθμοι κρυπτογραφίας.

3) simulator.py: Είναι το simulator tool που ζητείται στην τέταρτη
φάση του project. Τρέχει με την εξής εντολή:
    "python3 simulator.py"

-PRECONDITION: Πρέπει πρώτα να έχει τρέξει το πρόγραμμα risk_assessment_tool.py
και να έχει παραχθεί το αρχείο scan_result.json.

-INPUT: Το αρχείο scan_result.json

-OUTPUT: Αλλάζει τον πηγαίο κώδικα του προγράμματος ώστε να χρησιμοποιεί 
    SHA-3 που είναι safe post-quantum cryptographic algorithm. Εάν δεν μπορεί
    να αλλάξει τον πηγαίο κώδικα, τότε εμφανίζει στην κονσόλα ενημέρωση για το
    που υπάρχουν συναρτήσεις από vulnerable κρυπτογραφικούς αλγορίθμους.
    
##################################################################################