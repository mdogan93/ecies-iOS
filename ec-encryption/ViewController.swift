//
//  ViewController.swift
//  ec-encryption
//
//  Created by Mehmet Doğan on 14.02.2019.
//  Copyright © 2019 Mehmet Doğan. All rights reserved.
//

import UIKit
import Blockstack
import CryptoSwift

//protocol Serializable: Codable {
//    func serialize() -> Data?
//}
//
//extension Serializable {
//    func serialize() -> Data? {
//        let encoder = JSONEncoder()
//        return try? encoder.encode(self)
//    }
//
//}
//
//extension Data{
//    func jsonToString()->String{
//        var convertedString:String?
//        do {
//            let data1 =  try JSONSerialization.data(withJSONObject: self, options: JSONSerialization.WritingOptions.prettyPrinted) // first of all convert json to the data
//            convertedString = String(data: data1, encoding: String.Encoding.utf8) // the data will be converted to the string
//            print(convertedString) // <-- here is ur string
//            return convertedString!
//        } catch let myJSONError {
//            print(myJSONError)
//        }
//        return convertedString!
//    }
//}

class ViewController: UIViewController {

    @IBOutlet weak var txtDecrypted: UITextView!
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }


    @IBAction func decryption(_ sender: UIButton) {
        var testData = dataModel()
        testData.ciphertext = "fc5d25c3253585fa601b0076933c3962"
        testData.ephemPublicKey =  "04d33d0ed1481f6f379fa990ec4759739dd845d611e5550775c6f15bb3be941981d2fdf43905fa6005e5caca2a6b219fb392cda0b461f8c01a98d375b5e00d4537"
        testData.iv = "6912821b450859349b9c8e53b59eaee3"
        testData.mac = "c4389a8ba97238eec5eb78649740bb7d3c4fb020ef0393872f5a9b9c160bdc29"

        let jsonEncoder = JSONEncoder()
        let jsonData = try? jsonEncoder.encode(testData)
        let json = String(data: jsonData!, encoding: String.Encoding.utf8)

        let jsonDecoder = JSONDecoder()
        let dtsample = try! jsonDecoder.decode(dataModel.self, from: jsonData!)
        
        let newdata = decryptECIES(cipherObjectJSONString: json!,privateKey: "bfe861192b89df231018d77e8ed4df781f6aec1d3b134a304426c0f89e709e0a" )
        txtDecrypted.text = newdata!

    }
    
}

func decryptECIES(cipherObjectJSONString: String, privateKey: String) -> String? {
    let jsonDecoder = JSONDecoder()
    let jsonData = cipherObjectJSONString.data(using: .utf8)!
    let dtsample = try! jsonDecoder.decode(dataModel.self, from: jsonData)
    let out = Blockstack.shared.decryptContent(content: cipherObjectJSONString, privateKey: privateKey)
    return out?.plainText
}


struct dataModel : Codable{
    var ephemPublicKey:String?
    var iv:String?
    var mac:String?
    var ciphertext:String?
    
    private enum CodingKeys: String, CodingKey {
        case ephemPublicKey
        case iv
        case mac
        case ciphertext
    }

}
