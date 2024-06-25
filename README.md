# Vault API
 
Vault API compresses the input data bytes after that it creates a unique Master encryption key for that data to be encrypted, compressed encrypted data is stored in a Control Block. 

Next step is using RSA keys for assymetric encryption of the Master key which is also stored in a Control block.

Control Block is a data structure that holds the encrypted data, the encrypted master key with time and date of its creation. 

Control blocks are translated to XML form and attached a generated hash to bind the next block to the previous one and so creating a blockchain type structure in a XML document form.
After that the XML document containing the blockchain structure is signed with XML signature. Ensuring the validity and integrity of the input data.

All of the steps in the process are reversable.

# Java-Cryptography
Cryptography is the art and science of making a cryptosystem that is capable of providing information security.

Cryptography deals with the actual securing of digital data. It refers to the design of mechanisms based on mathematical algorithms that provide fundamental information 
security services. You can think of cryptography as the establishment of a large toolkit containing different techniques in security applications.

The art and science of breaking the cipher text is known as cryptanalysis.

Cryptanalysis is the sister branch of cryptography and they both co-exist. The cryptographic process results in the cipher text for transmission or storage. 
It involves the study of cryptographic mechanism with the intention to break them. Cryptanalysis is also used during the design of the new cryptographic techniques 
to test their security strengths.
 
