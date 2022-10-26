(ns vault.secret.transit
  "Reference: https://developer.hashicorp.com/vault/api-docs/secret/transit#create-key"
  (:require
    [vault.client.http :as http]
    [vault.client.mock :as mock]
    [vault.util :as u])
  (:import
    vault.client.http.HTTPClient
    vault.client.mock.MockClient))


(def default-mount
  "Default mount point to use if one is not provided."
  "transit")


(defprotocol API
  "Transit secret endpoints"

  (with-mount
    [client mount]
    "Return an updated client which will resolve secrets against the provided
    mount instead of the default. Passing `nil` will reset the client to the
    default.")

  (create-key
    [client key-name key-type opts]
    "Creates a new encryption key of the specified type.

    
    Options:
    - `:convergent-encryption` (boolean)
      When enabled, the key will support convergent encryption, where the same plaintext
      creates the same ciphertext. This requires `:derived` to be set to true.
    - `:derived` (boolean)
      Specifies if key deriviation is to be used. If enabled, all encrypt/decrypt requests to
      this named key must provide a context which is used for key deriviation.
    - `:exportable` (boolean)
      Enables keys to be exportable.
    - `:allow-plaintext-backup` (boolean)
      If set, enables taking backup of named key in the plaintext format.
    - `:key-size` (integer)
      The key size in bytes for algorithms that allow variable key sizes.
    - `:auto-rotate-period` (integer)
      The period at which this key should be rotate automatically.")

  (read-key
    [client key-name]
    "Returns information about a named encryption key")

  (delete-key
    [client key-name]
    "Deletes a named encryption key.")

  (update-key-configuration
    [cliet key-name opts]
    "Updates the configuration values for a given key.
    
    Options:
    - `:min-decryption-version` (integer)
      Specifies the minimum version of ciphertext allowed to be decrypted
    - `:min-encryption-version` (integer)
      Specifies the minimum version of the key that can be used to encrypt plaintext,
      sign payloads, or generate HMACs.
    - `:deletion-allowed` (boolean)
      Specifies if the key is allowed to be deleted
    - `:exportable` (boolean)
      Enables keys to be exportable.
    - `:allow-plaintext-backup` (boolean)
      If set, enables taking backup of named key in the plaintext format.
    - `:auto-rotate-period` (integer)
      The period at which this key should be rotate automatically."))


(extend-type MockClient

  API

  (with-mount
    [client mount]
    (if (some? mount)
      (assoc client ::mount mount)
      (dissoc client ::mount))))


(extend-type HTTPClient

  API

  (with-mount
    [client mount]
    (if (some? mount)
      (assoc client ::mount mount)
      (dissoc client ::mount)))

  (create-key
    [client key-name key-type opts]
    (let [mount (::mount client default-mount)
          api-path (u/join-path mount "keys" key-name)]
      (http/call-api
        client :post api-path
        {:content-type :json
         :body (assoc opts :type key-type)})))

  (read-key
    [client key-name]
    (let [mount (::mount client default-mount)
          api-path (u/join-path mount "keys" key-name)]
      (http/call-api
        client :get api-path
        {:handle-response u/kebabify-body-data})))

  (delete-key
    [client key-name]
    (let [mount (::mount client default-mount)
          api-path (u/join-path mount "keys" key-name)]
      (http/call-api
        client :delete api-path {})))

  (update-key-configuration
    [client key-name opts]
    (let [mount (::mount client default-mount)
          api-path (u/join-path mount "keys" key-name "config")]
      (http/call-api
        client :post api-path
        {:content-type :json
         :body (u/snakify-keys opts)
         :handle-response (fn [x] (println x) (u/kebabify-body-data x))}))))
