# STIX 2.0とElasticserachを活用した攻撃検知

本研究で使用したツールを公開しています。
以下の環境で動作確認済みです。
- ELKサーバ
	- Elasticsearch: 5.6.4
	- Logstash: 5.6.4
	- Python 3

- プロキシサーバ
	- Squid:3.3
	- Filebeat:5.5.1


- リアルタイム検知ツール<br/>
<a href="https://github.com/sisoc-tokyo/STIX2_ES_detection/tree/master/Logstash">リアルタイム検知ツールはこちら</a><br/>
　プロキシログをリアルタイムで受信した際に、logstashから起動される検知プログラム。<br/>
　プロキシログとブラックリストを突合し、該当するログを検知した場合は、アラートメールを送信する。<br/>
　また、"squid"インデックスの"indicator"フィールドにインディケータにマッチしたことを示すフラグ"matched"を付与する。<br/>
　Logstashが動作しているサーバに配置してください。<br/>

　使用方法は以下です。<br/>
　Logstashの起動時に、logstash.confを読み込むように指定します<br/>
  例）logstash -f /etc/logstash/conf.d/logstash.conf &<br/>
  Filebeatからログを受信したタイミングで検知プログラムsearch_blacklist.pyが呼び出されます。<br/>

- 過去ログの検知ツール<br/>
<a href="https://github.com/sisoc-tokyo/STIX2_ES_detection/tree/master/ES_management_PC">過去ログの検知ツールはこちら</a><br/>
　STIX 2.0形式のインディケータから通信先情報を抽出し、ブラックリストに登録する。<br/>
　抽出した通信先情報と過去のプロキシログを突合し、該当するログを検知した場合は、<br/>
　"squid"インデックスの"indicator"フィールドにインディケータにマッチしたことを示すフラグ"matched"を付与する。<br/>
　Elasticsearchを管理するためのPC（ElasticsearchのREST APIにアクセス可能なPC）に配置してください。<br/>

　使用方法は以下です。<br/>
　python input_report.py {ElasticsearchのIPアドレス}:9200 {STIX 2.0形式のjsonファイル}<br>
  例）python input_report.py 192.0.2.100:9200 apt1.json 

