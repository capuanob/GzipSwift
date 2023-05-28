#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import Foundation
import Gzip

let supported_compression_levels: [CompressionLevel] = [
    CompressionLevel.bestCompression,
    CompressionLevel.bestSpeed,
    CompressionLevel.defaultCompression,
    CompressionLevel.noCompression
]

@_cdecl("LLVMFuzzerTestOneInput")
public func GzipFuzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)
    let fuzz_choice = fdp.ConsumeIntegralInRange(from: 0, to: 2)

    let compression_level = fdp.PickValueInList(from: supported_compression_levels)
    let data: Data = fdp.ConsumeRemainingData()

    do {
        switch (fuzz_choice) {
        case 0:
            // Standard zip followed by unzip
            let compressedData: Data = try data.gzipped(level: compression_level)
            if data.isGzipped {
                let uncompressedData = try compressedData.gunzipped()

                if uncompressedData != data {
                    fatalError("Uncompressed data does not match original data")
                }
            }


        case 1:
            // Unzip proper zipped content
            if data.isGzipped {
                try data.gunzipped()
            }
        case 2:
            // Unzip invalid zipped content
            try data.gunzipped()
        default:
            fatalError("Invalid fuzz choice")
        }
    }
    catch is GzipError {
        return -1
    }
    catch let error {
        print(error.localizedDescription)
        print(type(of: error))
        exit(EXIT_FAILURE)
    }

    return 0;
}