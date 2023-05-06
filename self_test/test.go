package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

/*
User -> 存储用户信息 userdata。
Username: 用户名
UserDataUUID: 存放 userdata 的位置。
UserDataEncKey: 加密 UserDataUUID 的对称密钥，是确定值。
MacUUID: 存放验证 userdata 完整性文件的位置。
SignKey: 私钥，用来签名。
DecKey: 私钥，用来解密。
FilesMetaUUIDMap: file -> 存储 file 的 Metadata 的 UUID。
FilesMetaShareMap: 用来存储把 metadata 分享出去的副本的 UUID。便于 revoke()。 [reciname][filename]
*/
type User struct {
	Username          string
	UserDataUUID      uuid.UUID
	MacUUID           uuid.UUID
	UserDataEncKey    []byte
	SignKey           userlib.DSSignKey
	DecKey            userlib.PKEDecKey
	FilesSymKeys      map[string][]byte
	FilesMetaUUIDMap  map[string]uuid.UUID
	FilesMetaShareMap map[string]map[string]uuid.UUID
	FilesMetaReciMap  map[string]map[string]uuid.UUID
}

/*
FileMetaData -> 用来存储文件的元信息。
- FileUUIDs：文件的 UUID，用来从数据库中拉取。
- FileKey：加密文件所用的 SymKey。
- FileMacKay: 检验加密文件的 SymKey 是否被更改的验证文件。
- FileMacUUID: 检验文件 UUID 是否被修改。
*/
type FileMetaData struct {
	FileUUIDs    map[int]uuid.UUID
	FileKey      []byte
	FileMacUUIDs map[int]uuid.UUID
	FileSignKey  userlib.DSSignKey
	FileVerKey   userlib.DSVerifyKey
}

type ShareStruct struct {
	SymKey []byte
	UUIDs  map[string]uuid.UUID
}

type macShareStruct struct {
	ShareStructJSONbytes []byte
	MAC                  []byte
}

type ChannelShareStruct struct {
	SymKey []byte
	UUID   uuid.UUID
}

type ChannelMacShareStruct struct {
	ShareStructJSONbytes []byte
	MAC                  []byte
}

/*
以下的函数都用来处理 JSON 数据，这是因为 JSON 转化成 Byte 串以后体积太大。
所以需要进行压缩。
过程大概如下：500 Bytes 的 JSON 流 -(splitIntoRows)-> 100x5 的二维 Bytes 流。
-(公钥加密)-> 256x5 的二维 Bytes 流。 -> 一维 bytes 流。
*/
// sortedKeys 给 map[int][]byte 的键进行排序，以免展平后解码出现错误。
func sortedKeys(m map[int][]byte) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	for i := 0; i < len(keys)-1; i++ {
		for j := 0; j < len(keys)-i-1; j++ {
			if keys[j] > keys[j+1] {
				keys[j], keys[j+1] = keys[j+1], keys[j]
			}
		}
	}

	return keys
}

// flatten 将二维数组展平为 1 维，用于将二维 encJSON 展平。
func flatten(m map[int][]byte) []byte {
	keys := sortedKeys(m)

	var result []byte
	for _, k := range keys {
		result = append(result, m[k]...)
	}
	return result
}

func splitIntoRows(arr []byte, cols int) map[int][]byte {
	rows := make(map[int][]byte)

	j := 0
	for i := 0; i < len(arr); i += cols {
		end := i + cols
		if end > len(arr) {
			end = len(arr)
		}
		row := arr[i:end]
		rows[j] = row
		j += 1
	}
	return rows
}

// chunkByteSlice 用来把较大的数据分割成小块。
// 这个用来拆分数据而不是比特。
func chunkByteSlice(data []byte) map[int][]byte {
	chunks := make(map[int][]byte)
	j := 0
	for i := 0; i < len(data); i += 1000 {
		end := i + 1000
		if end > len(data) {
			end = len(data)
		}
		row := data[i:end]
		chunks[j] = row
		j += 1
	}
	return chunks
}

// encryptJSON 用来公钥加密 JSON byte 串。这是因为它的体积太大了。
// 返回的 length 用来存储每一条的长度，用来逆操作。
func encryptJSON(structJSON []byte, key userlib.PKEEncKey) (flatEncJSON []byte) {
	if len(structJSON) >= 100 {
		chunkJSON := splitIntoRows(structJSON, 100)
		encJSON := make(map[int][]byte)

		for i := range chunkJSON {
			encChunkJSON, err := userlib.PKEEnc(key, chunkJSON[i])
			if err != nil {
				return nil
			}
			encJSON[i] = encChunkJSON
		}
		flatEncJSON = flatten(encJSON)

		return flatEncJSON
	} else {
		encJSON, _ := userlib.PKEEnc(key, structJSON)
		return encJSON
	}

}

// decryptJSON 用私钥解密 JSON byte 串。
// 由于 map 的地址不固定，因此需要写一个冒泡排序把键进行排序。
// 这样展平的时候才不会出现 bug。
func decryptJSON(flatEncJSON []byte, key userlib.PKEDecKey) (structJSON []byte) {
	if len(flatEncJSON) > 256 {
		encJSON := splitIntoRows(flatEncJSON, 256)
		chunkJSON := make(map[int][]byte)
		for i := range encJSON {
			decChunkJSON, err := userlib.PKEDec(key, encJSON[i])
			if err != nil {
				return nil
			}
			chunkJSON[i] = decChunkJSON
		}
		structJSON = flatten(chunkJSON)

		return structJSON
	} else {
		structJSON, err := userlib.PKEDec(key, flatEncJSON)
		if err != nil {
			return nil
		}
		return structJSON
	}
}

func sortchunkKeys(m map[int]uuid.UUID) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	for i := 0; i < len(keys)-1; i++ {
		for j := 0; j < len(keys)-i-1; j++ {
			if keys[j] > keys[j+1] {
				keys[j], keys[j+1] = keys[j+1], keys[j]
			}
		}
	}

	return keys
}

func updateUserdataMAC(userdata *User) (err error) {
	userDataJSON, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	IV2 := userlib.RandomBytes(userlib.AESKeySizeBytes)
	encryptedUserData := userlib.SymEnc(userdata.UserDataEncKey, IV2, userDataJSON)
	macEncUserData, err := userlib.DSSign(userdata.SignKey, encryptedUserData)
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(userdata.MacUUID)
	userlib.DatastoreSet(userdata.MacUUID, macEncUserData)

	return nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// 如果注册名为空，则返回错误。
	if len(username) == 0 {
		err = errors.New("username can not be empty")
		return nil, err
	}

	// 通过 uuid.FromBytes 为这个 HashedUsername 生成一个 UUID。
	// 确定的。
	hashedUsername := userlib.Hash([]byte(username))
	hashedUsernameUUID, err := uuid.FromBytes(userlib.Argon2Key(hashedUsername, hashedUsername, 16))
	if err != nil {
		return nil, err
	}

	// 如果这个 HashedUsername 存在，则说明已经有人注册过了。
	collision, _ := userlib.DatastoreGet(hashedUsernameUUID)

	if collision != nil {
		err = errors.New("username existed")
		return nil, err
	}

	// 否则，把 UUID 和 HashedUsername 传入到 DataStore 中。
	userdata.Username = username
	userlib.DatastoreSet(hashedUsernameUUID, hashedUsername)

	// User 的 UUID 是确定的，由 username 和 password 确定。
	userUUID, err := uuid.FromBytes(userlib.Argon2Key([]byte(password), []byte(username), 16))
	if err != nil {
		return nil, err
	}
	userdata.UserDataUUID = userUUID

	// userdata 在 datastore 中需要被加密，并且是 deterministic 的，所以创建一个确定的密钥：
	// 这里使用 userUUID 和 password。
	userdata.UserDataEncKey = userlib.Argon2Key([]byte(password), []byte(userUUID.String()), 16)

	// MacUUID 用来确定验证 userdata 文件在数据库中的位置。
	userdata.MacUUID = uuid.New()

	// 私钥，一个用来解密，一个用来签名。
	var verifyKey userlib.DSVerifyKey
	var encKey userlib.PKEEncKey
	userdata.SignKey, verifyKey, err = userlib.DSKeyGen()
	encKey, userdata.DecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"_PKEEncKey", encKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"_DSVerifyKey", verifyKey)
	if err != nil {
		return nil, err
	}

	// 加密 userdata，并保存到 UUID 里。
	// userdata 的 UUID 和解密的 key 都是由用户名和密码确定的。
	userDataJSON, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	IV := userlib.RandomBytes(userlib.AESKeySizeBytes)
	encryptedUserData := userlib.SymEnc(userdata.UserDataEncKey, IV, userDataJSON)
	userlib.DatastoreSet(userdata.UserDataUUID, encryptedUserData)

	// 再在 DataStore 中保存 encryptedUserData 的 MAC。
	// 以后每次发生变动，都需要重新签名。
	macEncUserData, err := userlib.DSSign(userdata.SignKey, encryptedUserData)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userdata.MacUUID, macEncUserData)

	userdata.FilesSymKeys = make(map[string][]byte)
	userdata.FilesMetaUUIDMap = make(map[string]uuid.UUID)
	userdata.FilesMetaShareMap = make(map[string]map[string]uuid.UUID)
	userdata.FilesMetaReciMap = make(map[string]map[string]uuid.UUID)

	userdataptr = &userdata

	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	//先 hash 用户名。再通过 hashed username 来看看是否有。
	hashedUsername := userlib.Hash([]byte(username))
	hashedUsernameUUID, err := uuid.FromBytes(userlib.Argon2Key(hashedUsername, hashedUsername, 16))
	if err != nil {
		return nil, err
	}
	// 如果用户名不存在，则返回错误。
	collision, _ := userlib.DatastoreGet(hashedUsernameUUID)
	if collision == nil {
		err = errors.New("username not existed")
		return nil, err
	}

	// 通过键入的 username 和 password 来从 datastore 中找到用户的 userdata。
	// uuid 是根据 H(password|username) 创建的 uuid 值。
	userUUID, err := uuid.FromBytes(userlib.Argon2Key([]byte(password), []byte(username), 16))
	if err != nil {
		return nil, err
	}
	encryptedUserData, _ := userlib.DatastoreGet(userUUID)

	// 如果账号密码错误，则报错。
	if encryptedUserData == nil {
		err = errors.New("no userdata found")
		return nil, err
	}

	// 加密 userdata 使用的是对称加密，因此用同样的方法获得 SymEnc() 的 Key。
	// 整个 getuser 过程都应该是完全 deterministic 的，一旦引入随机，那就会出现错误。
	userDataEncKey := userlib.Argon2Key([]byte(password), []byte(userUUID.String()), 16)
	// 解密。
	userDataJSON := userlib.SymDec(userDataEncKey, encryptedUserData)
	// 把 JSON 数据转换成 User 的结构。
	err = json.Unmarshal(userDataJSON, &userdata)
	if err != nil {
		return nil, err
	}

	// 最后，验证 MAC 文件的完整性。
	// 给出一个报错。
	storedUserDataMAC, _ := userlib.DatastoreGet(userdata.MacUUID)
	verifyKey, _ := userlib.KeystoreGet(username + "_DSVerifyKey")
	// 比较 encryptedUserData 和 storedUserDataMAC。
	err = userlib.DSVerify(verifyKey, encryptedUserData, storedUserDataMAC)
	if err != nil {
		return nil, err
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	if userdata.FilesSymKeys == nil {
		userdata.FilesSymKeys = make(map[string][]byte)
	}
	if userdata.FilesMetaUUIDMap == nil {
		userdata.FilesMetaUUIDMap = make(map[string]uuid.UUID)
	}

	// 假如我的用户下面并没有这个文件，那么就创建它。
	if userdata.FilesMetaUUIDMap[filename] == uuid.Nil {
		var fileMetaData FileMetaData

		// 创建这个文件在低安全频道中的 key。
		fileMetaData.FileKey = userlib.Argon2Key([]byte(filename), userlib.RandomBytes(16), 16)
		fileMetaData.FileSignKey, fileMetaData.FileVerKey, err = userlib.DSKeyGen()
		if err != nil {
			return err
		}

		// 然后进行分块。块大小是 1000 Byte。
		chunks := chunkByteSlice(content)

		fileMetaData.FileUUIDs = make(map[int]uuid.UUID)
		fileMetaData.FileMacUUIDs = make(map[int]uuid.UUID)

		for i := range chunks {
			// 之后，对每一个块进行加密。并存储到对应的 UUID 里。
			// 因为引入了随机数，所以只需要一个 filekey 就可以。
			fileChunkUUID := uuid.New()
			IV1 := userlib.RandomBytes(userlib.AESKeySizeBytes)
			chunkedContent := chunks[i]
			encContent := userlib.SymEnc(fileMetaData.FileKey, IV1, chunkedContent)
			fileMetaData.FileUUIDs[i] = fileChunkUUID
			userlib.DatastoreSet(fileChunkUUID, encContent)

			// 之后，对每一个加密前的块进行签名。
			// 考虑到异步修改的问题，我们需要把这些钥匙存放在元信息里。
			macChunkUUID := uuid.New()
			macChunk, err := userlib.DSSign(fileMetaData.FileSignKey, encContent)
			if err != nil {
				return err
			}
			fileMetaData.FileMacUUIDs[i] = macChunkUUID
			userlib.DatastoreSet(macChunkUUID, macChunk)
		}

		// 加密并存储文件本体。文件本体的密钥和 UUID 都被记录在了 metadata 里。
		// 为该文件的 Metadata 生成一个 uuid。这个 uuid 是纯随机的。
		fileMetaDataUUID := uuid.New()

		// 加密并存储文件的 Metadata。加密 Metadata 的密钥是一把对称密钥。
		// 这把密钥通过分享文件时来传递。
		FileMetadataJSON, err := json.Marshal(fileMetaData)
		if err != nil {
			return err
		}

		// 创建一个新密钥。
		salt := userlib.RandomBytes(userlib.AESKeySizeBytes)
		IV1 := userlib.RandomBytes(userlib.AESKeySizeBytes)
		fileKey := userlib.Argon2Key([]byte(filename), salt, 16)
		userdata.FilesSymKeys[filename] = fileKey
		encFileMetadata := userlib.SymEnc(fileKey, IV1, FileMetadataJSON)
		userlib.DatastoreSet(fileMetaDataUUID, encFileMetadata)
		userdata.FilesMetaUUIDMap[filename] = fileMetaDataUUID

		// 最后，由于 userdata 发生了改变，因此需要更新 userdata 的 MAC 文件。
		err = updateUserdataMAC(userdata)
		if err != nil {
			return err
		}
		return nil
	}

	var fileMetadata FileMetaData

	// 将文件的 metadata 从加密的 JSON 数据解码出来。
	fileMetadataUUID := userdata.FilesMetaUUIDMap[filename]
	filekey := userdata.FilesSymKeys[filename]
	if fileMetadataUUID == uuid.Nil {
		err := errors.New("can not find the file")
		return err
	}

	// 之后，验证文件完整性。
	encFileMetadata, _ := userlib.DatastoreGet(fileMetadataUUID)
	fileMetadataJSON := userlib.SymDec(filekey, encFileMetadata)
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileMetadataJSON, &fileMetadata)
	if err != nil {
		return err
	}

	// 检验 MAC。
	// 如果有任何一个块被毁坏，则返回错误。

	for i := range fileMetadata.FileUUIDs {
		mac, _ := userlib.DatastoreGet(fileMetadata.FileMacUUIDs[i])
		encChunk, _ := userlib.DatastoreGet(fileMetadata.FileUUIDs[i])
		err = userlib.DSVerify(fileMetadata.FileVerKey, encChunk, mac)
		if err != nil {
			return err
		}
	}

	// 验证通过后，先删除原来的东西。
	for i := range fileMetadata.FileUUIDs {
		userlib.DatastoreDelete(fileMetadata.FileUUIDs[i])
		userlib.DatastoreDelete(fileMetadata.FileMacUUIDs[i])
	}

	// 并且这个 uuid 表本身也要重新声明。
	fileMetadata.FileUUIDs = nil
	fileMetadata.FileMacUUIDs = nil

	// 使用 make() 函数重新创建一个新的 map[int]uuid.UUID 对象
	fileMetadata.FileUUIDs = make(map[int]uuid.UUID)
	fileMetadata.FileMacUUIDs = make(map[int]uuid.UUID)

	// 然后进行分块。块大小是 1000 Byte。
	// 分块完之后重新进行 MAC 签署。
	chunks := chunkByteSlice(content)
	for j := range chunks {

		macUUID := uuid.New()
		fileMetadata.FileMacUUIDs[j] = macUUID

		chunkUUID := uuid.New()
		fileMetadata.FileUUIDs[j] = chunkUUID

		IV1 := userlib.RandomBytes(userlib.AESKeySizeBytes)
		encContent := userlib.SymEnc(fileMetadata.FileKey, IV1, chunks[j])
		userlib.DatastoreSet(chunkUUID, encContent)

		macChunk, err := userlib.DSSign(fileMetadata.FileSignKey, encContent)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(macUUID, macChunk)
	}

	// 最后，更新元信息。
	// 这个过程没有更新 userdata，因此不需要更新 MAC。
	userlib.DatastoreDelete(fileMetadataUUID)
	// 加密并存储文件的 Metadata。加密 Metadata 的密钥依然是之前那一把。
	FileMetadataJSON, err := json.Marshal(fileMetadata)
	if err != nil {
		return err
	}
	IV := userlib.RandomBytes(userlib.AESKeySizeBytes)
	encFileMetadata = userlib.SymEnc(filekey, IV, FileMetadataJSON)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMetadataUUID, encFileMetadata)
	return nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var fileMetadata FileMetaData

	// 将文件的 metadata 从加密的 JSON 数据解码出来。
	fileMetadataUUID := userdata.FilesMetaUUIDMap[filename]
	filekey := userdata.FilesSymKeys[filename]
	if fileMetadataUUID == uuid.Nil {
		err := errors.New("can not find the file")
		return nil, err
	}

	// 之后，验证文件完整性。
	encFileMetadata, _ := userlib.DatastoreGet(fileMetadataUUID)
	if encFileMetadata == nil {
		err := errors.New("can not find the file")
		return nil, err
	}

	fileMetadataJSON := userlib.SymDec(filekey, encFileMetadata)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(fileMetadataJSON, &fileMetadata)
	if err != nil {
		return nil, err
	}

	// 检验 MAC。
	// 如果有任何一个块被毁坏，则返回错误。
	for i := range fileMetadata.FileUUIDs {
		mac, _ := userlib.DatastoreGet(fileMetadata.FileMacUUIDs[i])
		encChunk, _ := userlib.DatastoreGet(fileMetadata.FileUUIDs[i])
		err = userlib.DSVerify(fileMetadata.FileVerKey, encChunk, mac)
		if err != nil {
			return nil, err
		}
	}

	// 最后，解码文件。
	keys := sortchunkKeys(fileMetadata.FileUUIDs)
	for i := range keys {
		encChunkContent, _ := userlib.DatastoreGet(fileMetadata.FileUUIDs[i])
		chunkContent := userlib.SymDec(fileMetadata.FileKey, encChunkContent)
		content = append(content, chunkContent...)
	}
	return content, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	// 将文件的 metadata 从加密的 JSON 数据解码出来。
	var fileMetadata FileMetaData
	fileMetadataUUID := userdata.FilesMetaUUIDMap[filename]
	if fileMetadataUUID == uuid.Nil {
		err := errors.New("can not find the filename")
		return err
	}
	encFileMetadata, _ := userlib.DatastoreGet(fileMetadataUUID)
	if encFileMetadata == nil {
		err := errors.New("can not find the file")
		return err
	}

	fileMetadataJSON := userlib.SymDec(userdata.FilesSymKeys[filename], encFileMetadata)

	err := json.Unmarshal(fileMetadataJSON, &fileMetadata)
	if err != nil {
		return err
	}

	// 检验 MAC。
	// 如果有任何一个块被毁坏，则返回错误。
	for i := range fileMetadata.FileUUIDs {
		mac, _ := userlib.DatastoreGet(fileMetadata.FileMacUUIDs[i])

		encChunk, _ := userlib.DatastoreGet(fileMetadata.FileUUIDs[i])
		err = userlib.DSVerify(fileMetadata.FileVerKey, encChunk, mac)
		if err != nil {
			return err
		}
	}

	// 首先，根据 metadata 得到最后一个 file chunk 的 UUID。
	maxKey := -1
	// 遍历 map。
	for key := range fileMetadata.FileUUIDs {
		if key > maxKey {
			maxKey = key
		}
	}
	encFile, _ := userlib.DatastoreGet(fileMetadata.FileUUIDs[maxKey])
	plainFile := userlib.SymDec(fileMetadata.FileKey, encFile)

	residual := 1000 - len(plainFile)

	// 如果最后一个块的长度 + content 的长度小于 1000，那也不用费劲巴力加密了。
	if len(content) < residual {
		plainFile = append(plainFile, content...)
		userlib.DatastoreDelete(fileMetadata.FileUUIDs[maxKey])
		IV := userlib.RandomBytes(userlib.AESKeySizeBytes)
		encContent := userlib.SymEnc(fileMetadata.FileKey, IV, plainFile)
		userlib.DatastoreSet(fileMetadata.FileUUIDs[maxKey], encContent)

		// 更新最后一个块的 MAC。
		userlib.DatastoreDelete(fileMetadata.FileMacUUIDs[maxKey])
		mac, err := userlib.DSSign(fileMetadata.FileSignKey, encContent)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileMetadata.FileMacUUIDs[maxKey], mac)

		return nil
	} else {
		// 否则，分头行动。
		contentR := content[:residual]
		plainFile = append(plainFile, contentR...)
		userlib.DatastoreDelete(fileMetadata.FileUUIDs[maxKey])
		IV := userlib.RandomBytes(userlib.AESKeySizeBytes)
		encContent := userlib.SymEnc(fileMetadata.FileKey, IV, plainFile)
		userlib.DatastoreSet(fileMetadata.FileUUIDs[maxKey], encContent)

		// 更新最后一个块的 MAC。
		userlib.DatastoreDelete(fileMetadata.FileMacUUIDs[maxKey])
		mac, err := userlib.DSSign(fileMetadata.FileSignKey, encContent)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileMetadata.FileMacUUIDs[maxKey], mac)

		contentL := content[residual:]
		chunkedContentL := chunkByteSlice(contentL)
		for j := range chunkedContentL {

			macUUID := uuid.New()
			fileChunkUUID := uuid.New()

			fileMetadata.FileUUIDs[j+maxKey+1] = fileChunkUUID
			fileMetadata.FileMacUUIDs[j+maxKey+1] = macUUID

			IV1 := userlib.RandomBytes(userlib.AESKeySizeBytes)
			encContent := userlib.SymEnc(fileMetadata.FileKey, IV1, chunkedContentL[j])
			userlib.DatastoreSet(fileChunkUUID, encContent)

			macChunk, err := userlib.DSSign(fileMetadata.FileSignKey, encContent)
			if err != nil {
				return err
			}
			fileMetadata.FileMacUUIDs[j+maxKey+1] = macUUID
			userlib.DatastoreSet(fileMetadata.FileMacUUIDs[j+maxKey+1], macChunk)

		}

		fileMetadataJSON, err := json.Marshal(fileMetadata)
		if err != nil {
			return err
		}

		userlib.DatastoreDelete(fileMetadataUUID)
		IV = userlib.RandomBytes(userlib.AESKeySizeBytes)
		encFileMetadata = userlib.SymEnc(userdata.FilesSymKeys[filename], IV, fileMetadataJSON)
		userlib.DatastoreSet(fileMetadataUUID, encFileMetadata)

		return nil
	}
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {

	fileMetadataUUID := userdata.FilesMetaUUIDMap[filename]

	// 没有这个文件，报错。
	if fileMetadataUUID == uuid.Nil {
		err := errors.New("file does not exist")
		return uuid.Nil, err
	}

	// 通过 uuid.FromBytes 为这个 HashedUsername 生成一个 UUID。
	// 确定的。
	hashedUsername := userlib.Hash([]byte(recipientUsername))
	hashedUsernameUUID, err := uuid.FromBytes(userlib.Argon2Key(hashedUsername, hashedUsername, 16))
	if err != nil {
		return uuid.Nil, err
	}

	// 如果这个 HashedUsername 存在，则说明已经有人注册过了。
	collision, _ := userlib.DatastoreGet(hashedUsernameUUID)
	if collision == nil {
		err = errors.New("recipient not exist")
		return uuid.Nil, err
	}

	// 接下来，创建邀请。
	var shareStruct ShareStruct
	var macShareStruct macShareStruct

	ssUUIDs := make(map[string]uuid.UUID)

	// channel 在以后用来进行树管理。
	channelUUID := uuid.New()
	ssUUIDs["channelUUID"] = channelUUID
	ssUUIDs["FileMetadataUUID"] = userdata.FilesMetaUUIDMap[filename]
	shareStruct.UUIDs = ssUUIDs

	invitationPtr = uuid.New()

	shareStruct.SymKey = userdata.FilesSymKeys[filename]

	pkeEncKey, _ := userlib.KeystoreGet(recipientUsername + "_PKEEncKey")
	invitationJSON, err := json.Marshal(shareStruct)
	if err != nil {
		return uuid.Nil, err
	}

	macShareStruct.ShareStructJSONbytes = invitationJSON
	mac, err := userlib.DSSign(userdata.SignKey, invitationJSON)
	if err != nil {
		return uuid.Nil, err
	}
	macShareStruct.MAC = mac

	macShareStructJSON, err := json.Marshal(macShareStruct)
	if err != nil {
		return uuid.Nil, err
	}

	// 用对方的公钥进行加密。
	EncMacShareStructJSON := encryptJSON(macShareStructJSON, pkeEncKey)

	// 存到不安全数据库中。
	userlib.DatastoreSet(invitationPtr, EncMacShareStructJSON)

	// 给自己的 sharemap 进行更新。
	if userdata.FilesMetaShareMap == nil {
		userdata.FilesMetaShareMap = make(map[string]map[string]uuid.UUID)
	}
	if userdata.FilesMetaShareMap[filename] == nil {
		userdata.FilesMetaShareMap[filename] = make(map[string]uuid.UUID)
	}
	userdata.FilesMetaShareMap[filename][recipientUsername] = channelUUID

	// 更新自己的 userdata MAC。
	// 最后，由于 userdata 发生了改变，因此需要更新 userdata 的 MAC 文件。
	err = updateUserdataMAC(userdata)
	if err != nil {
		return uuid.Nil, err
	}

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	if userdata.FilesMetaUUIDMap[filename] != uuid.Nil {
		err := errors.New("file already existed")
		return err
	}

	// 已经有这个文件，则报错。
	if userdata.FilesMetaUUIDMap == nil {
		userdata.FilesMetaUUIDMap = make(map[string]uuid.UUID)
	}

	// 拿到带 MAC 的结构数据。
	var invitation macShareStruct
	EncInvitationJSON, _ := userlib.DatastoreGet(invitationPtr)
	invitationJSON := decryptJSON(EncInvitationJSON, userdata.DecKey)
	err := json.Unmarshal(invitationJSON, &invitation)
	if err != nil {
		return err
	}

	ShareStructJSON := invitation.ShareStructJSONbytes
	MAC := invitation.MAC

	// 验证发送者和文件完整性。
	veriKey, _ := userlib.KeystoreGet(senderUsername + "_DSVerifyKey")
	err = userlib.DSVerify(veriKey, ShareStructJSON, MAC)
	if err != nil {
		return err
	}

	var shareStruct ShareStruct

	err = json.Unmarshal(ShareStructJSON, &shareStruct)

	// 最后，验证文件是否过期。
	encBytes, _ := userlib.DatastoreGet(shareStruct.UUIDs["FileMetadataUUID"])
	if encBytes == nil {
		return err
	}

	if userdata.FilesSymKeys == nil {
		userdata.FilesSymKeys = make(map[string][]byte)
	}
	userdata.FilesSymKeys[filename] = shareStruct.SymKey

	if userdata.FilesMetaUUIDMap == nil {
		userdata.FilesMetaUUIDMap = make(map[string]uuid.UUID)
	}
	userdata.FilesMetaUUIDMap[filename] = shareStruct.UUIDs["FileMetadataUUID"]

	if userdata.FilesMetaReciMap == nil {
		userdata.FilesMetaReciMap = make(map[string]map[string]uuid.UUID)
	}
	if userdata.FilesMetaReciMap[filename] == nil {
		userdata.FilesMetaReciMap[filename] = make(map[string]uuid.UUID)
	}
	userdata.FilesMetaReciMap[filename][senderUsername] = shareStruct.UUIDs["channelUUID"]

	err = updateUserdataMAC(userdata)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	// 首先，文件所有者将文件的 metadata 从加密的 JSON 数据解码出来。
	var fileMetadata FileMetaData
	var err error
	fileMetadataUUID := userdata.FilesMetaUUIDMap[filename]

	// 文件不存在，报错。
	if fileMetadataUUID == uuid.Nil {
		err := errors.New("file doesn't exist")
		return err
	}

	// 然后看看跟没跟接收者建立过公钥信道。没分享过，报错。
	if userdata.FilesMetaShareMap[filename][recipientUsername] == uuid.Nil {
		err := errors.New("file hasn't shared to this user before")
		return err
	}

	// 将文件的 metadata 从加密的 JSON 数据解码出来。
	filekey := userdata.FilesSymKeys[filename]

	// 验证文件完整性。
	encFileMetadata, _ := userlib.DatastoreGet(fileMetadataUUID)
	fileMetadataJSON := userlib.SymDec(filekey, encFileMetadata)
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileMetadataJSON, &fileMetadata)
	if err != nil {
		return err
	}

	// 检验 MAC。
	// 如果有任何一个块被毁坏，则返回错误。
	for i := range fileMetadata.FileUUIDs {
		mac, _ := userlib.DatastoreGet(fileMetadata.FileMacUUIDs[i])
		encChunk, _ := userlib.DatastoreGet(fileMetadata.FileUUIDs[i])
		err = userlib.DSVerify(fileMetadata.FileVerKey, encChunk, mac)
		if err != nil {
			return err
		}
	}

	// 没有问题后，首先把文件内容读出来。
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	// 然后，删库跑路！这一步不是必须的，但是我就是想这么干。
	for i := range fileMetadata.FileUUIDs {
		userlib.DatastoreDelete(fileMetadata.FileUUIDs[i])
		userlib.DatastoreDelete(fileMetadata.FileMacUUIDs[i])
	}
	userlib.DatastoreDelete(fileMetadataUUID)

	// 把它声明为空，方便下一步调用 storefile。
	userdata.FilesMetaUUIDMap[filename] = uuid.Nil
	userdata.FilesSymKeys[filename] = nil

	err = userdata.StoreFile(filename, content)
	if err != nil {
		return err
	}

	// 之后，在公钥信道上给所有自己分发的除了 recipientUsername 以外的接收者分发新的信息。
	for recipient := range userdata.FilesMetaShareMap[filename] {
		if recipient != recipientUsername {
			var updatedMetadata ChannelShareStruct
			PKEkey, _ := userlib.KeystoreGet(recipient + "_PKEEncKey")
			SymKey := userdata.FilesSymKeys[filename]
			metadataUUID := userdata.FilesMetaUUIDMap[filename]

			updatedMetadata.SymKey = SymKey
			updatedMetadata.UUID = metadataUUID

			updatedMetadataJSON, err := json.Marshal(updatedMetadata)
			if err != nil {
				return err
			}
			EncUpdatedMetadata, err := userlib.PKEEnc(PKEkey, updatedMetadataJSON)
			if err != nil {
				return err
			}

			var macUpdatedMetadata ChannelMacShareStruct
			macUpdatedMetadata.ShareStructJSONbytes = EncUpdatedMetadata
			mac, err := userlib.DSSign(userdata.SignKey, EncUpdatedMetadata)
			macUpdatedMetadata.MAC = mac

			macUpdatedMetadataJSON, err := json.Marshal(macUpdatedMetadata)
			if err != nil {
				return err
			}

			channelUUID := userdata.FilesMetaShareMap[filename][recipient]

			userlib.DatastoreSet(channelUUID, macUpdatedMetadataJSON)
		}
	}

	err = updateUserdataMAC(userdata)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	// 创建一个长度为 10000 的字节数组
	randomBytes1 := make([]byte, 9995)
	// 从加密随机源中读取随机字节
	_, err := rand.Read(randomBytes1)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// 创建一个长度为 10 的字节数组
	randomBytes2 := make([]byte, 100)
	// 从加密随机源中读取随机字节
	_, err = rand.Read(randomBytes2)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	userdata1, err := InitUser("alice", "123456")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	userdata2, err := InitUser("bob", "123456")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println(randomBytes1[0:10])

	err = userdata1.StoreFile("test", randomBytes1)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	ptr, err := userdata1.CreateInvitation("test", "bob")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	err = userdata2.AcceptInvitation("alice", ptr, "test")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	output, err := userdata2.LoadFile("test")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println(output[0:10])

	err = userdata1.RevokeAccess("test", "bob")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

}
