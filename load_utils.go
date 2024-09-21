package libv2ray

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	v2core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	serial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// func LoadJSONConfig(reader io.Reader) (*v2core.Config, error) {
// 	jsonConfig, err := serial.DecodeJSONConfig(reader)
// 	if err != nil {
// 		return nil, err
// 	}

// 	key, err := hex.DecodeString("16e8cd0fd6f1c66392527132143a5a56")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	if err != nil {
// 		panic(err)
// 	}
// 	for i := range jsonConfig.OutboundConfigs {
// 		outbound := &jsonConfig.OutboundConfigs[i] // Address of the outbound config
// 		if outbound.Protocol == "vless" || outbound.Protocol == "vmess" {
// 			if outbound.Settings != nil {
// 				updatedSettings, err := decryptAndUpdateID(outbound.Settings, key)
// 				if err != nil {
// 					panic(err) // Or handle the error gracefully
// 				}
// 				outbound.Settings = updatedSettings // Assign the updated RawMessage directly
// 			}
// 		}
// 	}

// 	pbConfig, err := jsonConfig.Build()
// 	if err != nil {
// 		return nil, nil
// 	}

// 	return pbConfig, nil
// }

// func decryptAndUpdateID(settingsJSON *json.RawMessage, key []byte) (*json.RawMessage, error) {
// 	// 1. Unmarshal into the struct with RawMessage for the ID
// 	var Settings struct {
// 			Vnext []struct {
// 				Users []struct {
// 					ID json.RawMessage `json:"id"`
// 				} `json:"users"`
// 			} `json:"vnext"`
// 		}

// 	if err := json.Unmarshal(*settingsJSON, &Settings); err != nil {
// 		return nil, fmt.Errorf("error unmarshaling settings: %w", err)
// 	}

// 	// 2. Decrypt and update the ID for each user
// 	if len(Settings.Vnext) > 0 { // Check if Vnext is not empty
//         for i := range Settings.Vnext {
//             for j := range Settings.Vnext[i].Users {
//                 user := &Settings.Vnext[i].Users[j]

//                 decryptedID, err := decryptID(user.ID, key)
//                 if err != nil {
//                     return nil, fmt.Errorf("error decrypting ID: %w", err)
//                 }
//                 user.ID = json.RawMessage(`"` + decryptedID + `"`)
//             }
//         }
//     }

// 	// 3. Marshal the modified config back to JSON
// 	updatedJSON, err := json.Marshal(Settings)
// 	if err != nil {
// 		return nil, fmt.Errorf("error marshaling updated settings: %w", err)
// 	}

// 	    // Convert []byte to *json.RawMessage
// 	rawMessage := json.RawMessage(updatedJSON)
// 	return &rawMessage, nil // Now return a pointer to json.RawMessage
// }

func LoadJSONConfig(reader io.Reader) (*v2core.Config, error) {
	// 1. Decode the JSON configuration
	jsonConfig, err := serial.DecodeJSONConfig(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON config: %w", err)
	}

	// 2. Prepare your decryption key
	key, err := hex.DecodeString("16e8cd0fd6f1c66392527132143a5a56")
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// 3. Process and update outbound configurations
	for i := range jsonConfig.OutboundConfigs {
		outbound := &jsonConfig.OutboundConfigs[i]
		if outbound.Protocol == "vless" || outbound.Protocol == "vmess" {
			updatedOutbound, err := processOutboundConfig(outbound, key)
			if err != nil {
				return nil, fmt.Errorf("failed to process outbound config: %w", err)
			}
			jsonConfig.OutboundConfigs[i] = updatedOutbound 
		}
	}

	// 4. Build and return the V2Ray config
	pbConfig, err := jsonConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build V2Ray config: %w", err)
	}
	return pbConfig, nil
}

func processOutboundConfig(config *conf.OutboundDetourConfig, key []byte) (conf.OutboundDetourConfig, error) {
	// Unmarshal settings to a map for easier manipulation
	var settingsMap map[string]interface{}
	settingsJSON, _ := json.Marshal(config.Settings) // Convert to JSON
	json.Unmarshal(settingsJSON, &settingsMap)

	// Access and potentially decrypt 'id' in settings
	if vnext, ok := settingsMap["vnext"].([]interface{}); ok {
		for _, v := range vnext {
			vMap, ok := v.(map[string]interface{})
			if !ok {
				continue // Skip if type assertion fails
			}
			if users, ok := vMap["users"].([]interface{}); ok {
				for _, u := range users {
					userMap, ok := u.(map[string]interface{})
					if !ok {
						continue 
					}
					// Decrypt and update 'id'
					if encryptedID, ok := userMap["id"].(string); ok {
						decryptedID, err := decryptID([]byte(encryptedID), key)
						if err != nil {
							return *config, fmt.Errorf("failed to decrypt ID: %w", err)
						}
						userMap["id"] = decryptedID 
					}
				}
			}
		}
	}

	// Marshal the updated settings back
	updatedSettingsJSON, _ := json.Marshal(settingsMap)
	json.Unmarshal(updatedSettingsJSON, &config.Settings)

	return *config, nil
}


// Example decryption function - Adapt to your actual encryption method
func decryptID(encryptedID json.RawMessage, key []byte) (string, error) {
    // 1. Remove quotes from the raw message (if present)
    encryptedStr := string(encryptedID)
    encryptedStr = strings.Trim(encryptedStr, "\"") 

    // 2. Base64 decode the encrypted string
    ciphertext, err := base64.StdEncoding.DecodeString(encryptedStr)
    if err != nil {
        return "", fmt.Errorf("base64 decoding error: %w", err)
    }

    // ... Your AES-GCM decryption logic here ...
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("error creating cipher: %w", err)
	}

	nonceSize := 12 
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("error creating GCM: %w", err)
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("error decrypting: %w", err)
	}

    return string(plaintext), nil 
}