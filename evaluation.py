import pickle
import configparser

def get_confusion_matrix(payloads: list, labels: list, signatures: list):
    labelset = dict()
    for payload, label in zip(payloads, labels):
        if label not in labelset.keys():
            labelset[label] = 0

        for sign, freq in signatures:
            if sign in payload:
                labelset[label] = 1

    tp = tn = fp = fn = 0
    for label, pred in labelset.items():
        if label=='unknown':
            continue
        
        true = 1
        if 'benign' in label.lower():
            true = 0
        
        if true==0 and pred==0:
            tn += 1
        elif true==0 and pred==1:
            fp += 1
        elif true==1 and pred==0:
            fn += 1
        else:
            tp += 1
    
    return tp, tn, fp, fn

if __name__ == '__main__':

    properties = configparser.ConfigParser()
    properties.read('config.ini')

    payload_path = properties.get('PATH', 'payload_path')
    label_path = properties.get('PATH', 'label_path')
    signature_path = properties.get('PATH', 'signature_path')
    stopword_path = properties.get('PATH', 'stopword_path')

    with open(payload_path, 'rb') as f:
        payloads = pickle.load(f)

    with open(label_path, 'rb') as f:
        labels = pickle.load(f)

    print(f"标签总数: {len(labels)}")
    print(f"前 10 个标签: {labels[:10]}")

    ## signatures 몇 개 쓸건지 필터링 필요
    with open(signature_path, 'rb') as f:
        group_signatures = pickle.load(f) # 1. 修改变量名，加载字典

    # 2. 核心修复：解包签名字典为列表
    signatures = []
    for cluster_label, (sigs, count) in group_signatures.items():
        # sigs 是 [(sign, freq)] 列表
        signatures.extend(sigs) 

    # 3. 诊断性代码：检查生成的签名 (可选，但推荐保留)
    print(f"生成的签名总数: {len(signatures)}")
    print(f"前 5 个签名 (特征, 频率): {signatures[:5]}")
    
    ## stopword (AWL) 사용방법 필터링 추가 필요
    with open(stopword_path, 'rb') as f:
        stopwords = pickle.load(f)

    # 4. 传入正确的签名列表
    print(get_confusion_matrix(payloads, labels, signatures))