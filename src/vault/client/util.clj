(ns ^:no-doc vault.client.util
  "Vault implementation utilities."
  (:require
    [clojure.string :as str]
    [clojure.walk :as walk])
  (:import
    java.security.MessageDigest
    java.time.Instant
    java.util.Base64))


;; ## Time

(defn now
  "Returns the current time as an `Instant`. Mostly useful for rebinding in
  tests."
  ^Instant
  []
  (Instant/now))


(defn now-milli
  "Return the current time in epoch milliseconds."
  []
  (.toEpochMilli (now)))


;; ## Keywords

(defn kebab-keyword
  "Converts underscores to hyphens in a string or unqualified keyword. Returns
  a simple kebab-case keyword."
  [k]
  (-> k name (str/replace "_" "-") keyword))


(defn snake-keyword
  "Converts hyphens to underscores in a string or keyword. Returns a simple
  snake-case keyword."
  [k]
  (-> k name (str/replace "-" "_") keyword))


(defn walk-keys
  "Update the provided data structure by calling `f` on each map key."
  [data f]
  (walk/postwalk
    (fn xform
      [x]
      (if (map? x)
        (into (empty x)
              (map (juxt (comp f key) val))
              x)
        x))
    data))


(defn kebabify-keys
  "Walk the provided data structure by transforming map keys to kebab-case
  keywords."
  [data]
  (walk-keys data kebab-keyword))


;; ## Encoding

(defn hex-encode
  "Encode an array of bytes to hex string."
  ^String
  [^bytes data]
  (str/join (map #(format "%02x" %) data)))


(defn base64-encode
  "Encode the given data as base-64. If the input is a string, it is
  automatically coerced into UTF-8 bytes."
  [data]
  (.encodeToString
    (Base64/getEncoder)
    ^bytes
    (if (string? data)
      (.getBytes ^String data "UTF-8")
      data)))


(defn base64-decode
  "Decode the given base-64 string into byte data."
  ^bytes
  [data]
  (.decode (Base64/getDecoder) (str data)))


(defn sha-256
  "Hash string data with the SHA-2 256 bit algorithm. Returns the digest as a
  hex string."
  [s]
  (let [hasher (MessageDigest/getInstance "SHA-256")
        str-bytes (.getBytes (str s) "UTF-8")]
    (.update hasher str-bytes)
    (hex-encode (.digest hasher))))
