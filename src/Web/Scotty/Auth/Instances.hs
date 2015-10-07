{-# LANGUAGE OverloadedStrings #-}

module Web.Scotty.Auth.Instances where 

import Web.Scotty.Auth.Types

import Control.Monad
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as BL

instance Token t => ToJSON (AuthToken t) where 
    toJSON (AuthToken e t) = object ["exp" .= e, "tok" .= (B.unpack . serialize $ t)]
    
instance Token t => FromJSON (AuthToken t) where 
    parseJSON (Object v) = do 
        e <- v .: "exp"
        mtok <- fmap (deserialize . B.pack) $ v.: "tok"
        maybe mzero (return . AuthToken e) mtok
    parseJSON _ = mzero

instance Token t => Token (AuthToken t) where 
    serialize = B.concat . BL.toChunks . encode
    deserialize = decode . BL.fromChunks . (:[])