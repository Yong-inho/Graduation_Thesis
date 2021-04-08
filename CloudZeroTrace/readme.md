# Oblivious cache

## Build 
- make

## Usage
- execute : ./app (no command line arguments)
- temporal did size : 8bytes
- temporal did_docs size : 32bytes
- currently dynamic did and did_docs size is not supported

## different from original PathORAM
- We need to indexing cache by did(type:string) but PathORAM uses integer indexing.
- So new data structure 'DID_map' is defined to mapping did(type:string) to block_id(type:unint32_t)
