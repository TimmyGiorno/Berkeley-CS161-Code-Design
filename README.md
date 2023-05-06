# Project 2 Starter Code

## 0. Basic Information and Operation

This personal project implementation is for [UC Berkeley CS161 Project2](https://sp23.cs161.org/proj2/), spring 2023.

Implementation are realized in `client/client.go`, tests in `client_test/client_test.go`.

run `go test -v` inside of the `client_test` directory to test the implementation.


## 1. Main Data Structures

The user struct is defined below:

```go
type User struct {  
Username string  
UserDataUUID uuid.UUID  
MacUUID uuid.UUID  
UserDataEncKey []byte  
SignKey userlib.DSSignKey  
DecKey userlib.PKEDecKey  
FilesSymKeys map[string][]byte  
FilesMetaUUIDMap map[string]uuid.UUID  
FilesMetaShareMap map[string]map[string]uuid.UUID  
FilesMetaReciMap map[string]map[string]uuid.UUID  
}
```

where:
- `UserDataUUID`: The UUID where encrypted userdata is stored.  
- `UserDataEncKey`: The deterministic SymKey to encrypt UserDataUUID.
- `MacUUID`: The UUID where MAC for userdata is stored.  
-  `SignKey`: Private key to sign.  
- `DecKey`: Private key to decrypt.  
- `FilesSymKeys`: Symkeys to encrypt file metadata.
- `FilesMetaUUIDMap`: The UUID where file metadata is stored.  
- `FilesMetaShareMap`: The UUID to update crypto information. (You will see it later).
- `FilesMetaReciMap`: The UUID to update crypto information. (You will see it later).

The file metadata struct is defined below:

```go
type FileMetaData struct {  
FileUUIDs map[int]uuid.UUID  
FileKey []byte  
FileMacUUIDs map[int]uuid.UUID  
FileSignKey userlib.DSSignKey  
FileVerKey userlib.DSVerifyKey  
}
```

- `UserDataUUID`: The UUIDs where encrypted file segments are stored.
- `FileKey`: SymKey to encrypt the segmented filedata.
- `FileMacUUIDs`: The UUIDs where MACs for encrypted file segments are stored.
- `SignKey` and `VerKey`: Signature and verification for asynchronous operations.

---
## 2. Functions

#### 2.1. InitUser()
- First, the client determines if the length of username is 0;
- Second, the client hashes the useranme to get deterministic UUID for detecting username collision;
- Then, the client makes a new `User` struct for this username. The verification key and encrypation key will be stored in key store for future use, named as `username+"_PKEEncKey"` and `username+"_DSVerifyKey"`;
- A symmetric key is created to encrypt the userdata to store in the insecure datastore. The UUID to store userdata and the symmetirc are both deterministic so that everytime the user can log in normally.
```go
userdata.UserDataEncKey = userlib.Argon2Key([]byte(password), []byte(userUUID.String()), 16)
userUUID, err := uuid.FromBytes(userlib.Argon2Key([]byte(password), []byte(username), 16))
```
- Finally, generate an MACUUID and MAC File based on the `SignKey`. Everytime the userdata is updated, the MAC will be updated too.

#### 2.2. GetUser()
- First, the client hashes the useranme to get deterministic UUID for detecting username existence;
- Then, the client calculate the UserDataEncKey and userUUID to get and decrypt the userdata. The plaintext will be unmarshalled by `json.unmarshal`  to convert to a User struct.
- Finally, the client verify the integrity of the userdata from cryptotext based on the verification key. 

#### 2.3. StoreFile()
- First, determine if the file exists in the userdata and the integrity of the file.
- If not, the client will generate a new file metadata for it. The UUID of the metadata and the SymKey to encrypt the metadata will be stored in the userdata. Since the userdata has been updated, it needs to be signed again.
- The file will be segmented, and different segment will be encrypted, signed, finally stored in the datastore seperately. The UUID for diffrent segment and MAC for this segment will be stored in the filemetadata.
- If the file has already existed in the userdata, then the client will delete the original file segments, MACs, and rewrite the new file. The next process will be as same as to generate a new file.

#### 2.4. AppendtoFile()
- First, determine if the file exists in the userdata and the integrity of the file.
- Then, according to the index, starting from the last unfilled segment, the last segment is filled to 1000 Bytes first, and then the rest is chunked and added. metadata needs to be modified and re-signed.

#### 2.5. LoadFile()
- First, determine if the file exists in the userdata and the integrity of the file.
- After that, the segments are spliced according to the index order.


#### 2.6. CreateInvitation()
- First, verify the existence and integrity of the file.
- Then, encrypt the SymKey and UUID of the encrypted file metadata, and a future channel UUID by recipient's PubEncKey in the keystore.
- Sign this ciphertext by the user's SigKey. Store these in the invitation UUID.
- Finally, make `sender.Filesharemap[filename][recipientName]=channel UUID'.

#### 2.7. AcceptInvitation()
- First, verify that this data is from the sender;
- Then, store the SymKey and UUID of the filemetada in the userdata.
- Finally, make  `sender.Filerecimap[filename][recipientName]=channel UUID'.


#### 2.8. RevokeAccess()
- First, verify the existence and integrity of the file.
- Then, use `user.LoadFile()` to get the content.
- Delete the file metadata and the file segments. Make `userdata.SymKey[filename]=nil, userdata.FilesMetaUUIDMap[filename]=uuid.Nil`.
- Store the content again by `user.StoreFile()`.
- Finally, for those recipients whose access is not revoked, the owner of the file resend the `SymKey[filename]` and `FileMetadataUUID` to them from the channel. The contents will be encrypted by recipients' public keys.
- The receivers decrypt this updated data and distribute it to different receivers via public key encryption, and so on. Note that this process occurs when the receivers call the operation associated with this file again.


---
## 3. Analaysis and Helper Methods

#### 3.1. Confidentiality
Each key corresponds to only one use, so it's good to keep the information from being compromised. When encrypting different segments of the same file, confidentiality is also guaranteed due to the presence of random numbers, even though the same symmetric key is used.

#### 3.2. Integrity
- MAC is added to each operation for verification. The first operation of each function is to verify file integrity.
- When transmitting invitations, sign the encrypted content instead of the plaintext.

#### 3.3. Efficiency
- When performing appendtoFile operations, only the last block is started, thus ensuring good efficiency.
- To ensure confidentiality, when it comes to file overwriting, RevokeAccess and other operations, all the original files are deleted, sacrificing some time.
- Name conflict issues do not arise unless the file is shared.


---
## 4. Issues

#### 4.1. Revokeaccess() about the Shared Structure Tree

When you revoke a user's access to a file, you are not essentially disabling access, but rather re-encrypting the file and putting the new metadata in a new location. This key passing process is done over the previously established channel.

This leads to a problem. Suppose A transmits to B, C and C transmits to D. A revokes B's privileges, but C does not update the file and distribute the new key, so D will not be able to access the file until C confirms it.

However, I don't think this is a problem, and again, this trade-off is a sacrifice of efficiency for confidentiality. A revoked B will not be able to access this file or perform malicious operations because the file and the file's metadata have been encrypted and moved to a new location. This also implies the idea that this file distribution system is highly privileged, so once RevokeAccess() is called, that means at least some wrongdoing is taking place.

#### 4.2. The storages of the Keys

The encrypted file and the key used to sign the file can also be stored in the user's userdata, which intuitively does not affect confidentiality.
