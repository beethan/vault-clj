(ns vault.client.mock
  "A mock in-memory Vault client for local testing."
  (:require
    [clojure.edn :as edn]
    [clojure.java.io :as io]
    [clojure.string :as str]
    [vault.auth :as auth]
    [vault.client.flow :as f]
    [vault.client.proto :as proto]))


;; ## Mock Client

;; - `flow`
;;   Control flow handler.
;; - `auth`
;;   Atom containing the authentication state.
;; - `memory`
;;   Mock memory storage.
(defrecord MockClient
  [flow auth memory]

  proto/Client

  (auth-info
    [_]
    @auth)


  (authenticate!
    [this auth-info]
    (let [auth-info (if (string? auth-info)
                      {::auth/client-token auth-info}
                      auth-info)]
      (when-not (and (map? auth-info) (::auth/client-token auth-info))
        (throw (IllegalArgumentException.
                 "Client authentication must be a map of information containing a client-token.")))
      (reset! auth auth-info)
      this)))


;; ## Constructors

;; Privatize automatic constructors.
(alter-meta! #'->MockClient assoc :private true)
(alter-meta! #'map->MockClient assoc :private true)


(defn- load-fixtures
  "Helper method to load fixture data from a path. The path may resolve to a
  resource on the classpath, a file on the filesystem, or be `-` to specify no
  data."
  [path]
  (when (not= path "-")
    (some->
      (or (io/resource path)
          (let [file (io/file path)]
            (when (.exists file)
              file)))
      (slurp)
      (edn/read-string))))


(defn- load-init
  "Load the initial data specified by the given value. Accepts a map of data
  directly, or a `mock:` scheme URN with a path to fixture data to load, or
  `mock:-` for an empty initial dataset."
  [init]
  (cond
    (map? init)
    init

    (str/starts-with? (str init) "mock:")
    (let [path (subs (str init) 5)]
      (or (load-fixtures path) {}))

    :else
    (throw (IllegalArgumentException.
             (str "Mock client must be constructed with a map of data or a URN with scheme 'mock': "
                  (pr-str init))))))


(defn mock-client
  "Constructs a new mock Vault client. Accepts a URI address for loading mock
  data, or may be given a map of initial values to directly populate the
  in-memory state.

  Client behavior may be controlled with options:

  - `:flow`
    Custom control flow handler for requests. Defaults to `sync-handler`."
  ([]
   (mock-client {}))
  ([init & {:as opts}]
   (let [data (load-init init)]
     (map->MockClient
       (merge {:flow f/sync-handler}
              opts
              {:auth (auth/new-state)
               :memory (atom data :validator map?)})))))


;; ## Request Functions

(defn ^:no-doc success-response
  "Helper which uses the handler to generate a successful response."
  [client data]
  (let [handler (:flow client)]
    (f/call
      handler nil
      (fn success
        [state]
        (f/on-success! handler state data)))))


(defn ^:no-doc error-response
  "Helper which uses the handler to generate an error response."
  [client ex]
  (let [handler (:flow client)]
    (f/call
      handler nil
      (fn error
        [state]
        (f/on-error! handler state ex)))))
