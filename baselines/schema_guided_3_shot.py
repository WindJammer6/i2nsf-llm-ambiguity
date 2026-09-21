from openai import OpenAI
import csv

OPENAI_API_KEY = "YOUR-OPENAI-API-KEY-HERE"
client = OpenAI(api_key=OPENAI_API_KEY)
model = "gpt-4o-mini"

def generate_policy(policy_text, model="gpt-4o-mini"):
    """
    Converts natural language policy into an XML security policy.
    Includes three intent-policy examples and IETF schema context.
    """
    # Three intent-policy examples used only by this 3-shot baseline.
    example_input1 = "Allow students located in Central Singapore (SG-01) to access the online examination portal on 15 August 2025 from 09:00 to 12:00."
    example_output1 = """
<?xml version="1.0" encoding="UTF-8"?>
<endpoint-groups xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
  <user-group>
    <name>students</name>
    <ipv4-prefix>198.51.100.0/24</ipv4-prefix>
  </user-group>
  <device-group>
    <name>online-examination-portal</name>
    <ipv4-prefix>203.0.113.10/32</ipv4-prefix>
  </device-group>
  <location-group>
    <country>SG</country>
    <region>SG-01</region>
    <city>Singapore</city>
    <ipv4-prefix>198.51.100.0/24</ipv4-prefix>
  </location-group>
</endpoint-groups>

<i2nsf-cfi-policy xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
  <name>allow_central_singapore_exam_portal_access</name>
  <rules>
    <name>allow_students_during_scheduled_exam</name>
    <condition>
      <firewall>
        <source>students</source>
        <destination>online-examination-portal</destination>
      </firewall>
      <context>
        <time>
          <start-date-time>2025-08-15T09:00:00+08:00</start-date-time>
          <end-date-time>2025-08-15T12:00:00+08:00</end-date-time>
        </time>
        <geographic-location>
          <source>
            <country>SG</country>
            <region>SG-01</region>
            <city>Singapore</city>
          </source>
        </geographic-location>
      </context>
    </condition>
    <action>
      <primary-action>
        <action>pass</action>
      </primary-action>
    </action>
  </rules>
</i2nsf-cfi-policy>"""

    example_input2 = "Block access to online gambling websites from all devices."
    example_output2 = """
<?xml version="1.0" encoding="UTF-8"?>
<endpoint-groups xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
  <url-group>
    <name>online-gambling-websites</name>
    <url>https://gambling.example</url>
  </url-group>
</endpoint-groups>

<i2nsf-cfi-policy xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
  <name>block_online_gambling_websites</name>
  <rules>
    <name>block_gambling_sites_for_all_devices</name>
    <condition>
      <url-category>
        <url-name>online-gambling-websites</url-name>
      </url-category>
    </condition>
    <action>
      <primary-action>
        <action>drop</action>
      </primary-action>
    </action>
  </rules>
</i2nsf-cfi-policy>"""

    example_input3 = "Permit environmental sensors to send HTTPS traffic to the air-quality monitoring platform daily between 08:00 and 18:00."
    example_output3 = """
<?xml version="1.0" encoding="UTF-8"?>
<endpoint-groups xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface">
  <device-group>
    <name>environmental-sensors</name>
    <ipv4-prefix>192.0.2.0/24</ipv4-prefix>
    <application-protocol xmlns:i2nsfmi="urn:ietf:params:xml:ns:yang:ietf-i2nsf-monitoring-interface">i2nsfmi:https</application-protocol>
  </device-group>
  <device-group>
    <name>air-quality-monitoring-platform</name>
    <ipv4-prefix>203.0.113.20/32</ipv4-prefix>
    <application-protocol xmlns:i2nsfmi="urn:ietf:params:xml:ns:yang:ietf-i2nsf-monitoring-interface">i2nsfmi:https</application-protocol>
  </device-group>
</endpoint-groups>

<i2nsf-cfi-policy xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-cons-facing-interface" xmlns:i2nsfmi="urn:ietf:params:xml:ns:yang:ietf-i2nsf-monitoring-interface">
  <name>permit_air_quality_sensor_traffic</name>
  <rules>
    <name>allow_environmental_sensors_daily</name>
    <condition>
      <firewall>
        <source>environmental-sensors</source>
        <destination>air-quality-monitoring-platform</destination>
      </firewall>
      <context>
        <time>
          <period>
            <start-time>08:00:00</start-time>
            <end-time>18:00:00</end-time>
          </period>
          <frequency>daily</frequency>
        </time>
        <application>
          <protocol>i2nsfmi:https</protocol>
        </application>
        <device-type>
          <device>iot-device</device>
        </device-type>
      </context>
    </condition>
    <action>
      <primary-action>
        <action>pass</action>
      </primary-action>
    </action>
  </rules>
</i2nsf-cfi-policy>"""
    # Load additional context from I2NSF's official IETF draft
    ietf_context = """
    The I2NSF schema follows an Event-Condition-Action (ECA) model. XML policies can have the following headers:
    
  +--rw i2nsf-cfi-policy* [name]
  |  +--rw name                   string
  |  +--rw language?              string
  |  +--rw priority-usage?        identityref
  |  +--rw resolution-strategy?   identityref
  |  +--rw rules* [name]
     |  +--rw name         string
     |  +--rw priority?    uint8
     |  +--rw event
     |  |  +--rw system-event*   identityref
     |  |  +--rw system-alarm*   identityref 
     |  +--rw condition
	 |	|  +--rw firewall
		 |  |  +--rw source*                     union
		 |  |  +--rw destination*                union
		 |  |  +--rw transport-layer-protocol?   identityref
		 |  |  +--rw range-port-number* [start end]
		 |  |  |  +--rw start    inet:port-number
		 |  |  |  +--rw end      inet:port-number
		 |  |  +--rw icmp
		 |  |     +--rw message*   identityref
	 |	|  +--rw ddos
		 |  |  +--rw rate-limit
		 |  |     +--rw packet-rate-threshold?   uint64
		 |  |     +--rw byte-rate-threshold?     uint64
		 |  |     +--rw flow-rate-threshold?     uint64
	 |	|  +--rw anti-virus
		 |  |  +--rw profile*   string
		 |  |  +--rw exception-files*   string
	 |	|  +--rw payload
		 |  |  +--rw content*   -> /threat-prevention/payload-content/name
	 |	|  +--rw url-category
		 |  |  +--rw url-name?   -> /endpoint-groups/url-group/name
	 |	|  +--rw voice
		 |  |  +--rw source-id*        -> /endpoint-groups/voice-group/name
		 |  |  +--rw destination-id*   -> /endpoint-groups/voice-group/name
		 |  |  +--rw user-agent*       string
	 |  |  +--rw context
		 |  |  +--rw time
		 |  |  |  +--rw start-date-time?   yang:date-and-time
		 |  |  |  +--rw end-date-time?     yang:date-and-time
		 |  |  |  +--rw period
		 |  |  |  |  +--rw start-time?   time
		 |  |  |  |  +--rw end-time?     time
		 |  |  |  |  +--rw day*          day
		 |  |  |  |  +--rw date*         int8
		 |  |  |  |  +--rw month* [start end]
		 |  |  |  |     +--rw start    string
		 |  |  |  |     +--rw end      string
		 |  |  |  +--rw frequency?         enumeration
		 |  |  +--rw application
		 |  |  |  +--rw protocol*   identityref
		 |  |  +--rw device-type
		 |  |  |  +--rw device*   identityref
		 |  |  +--rw users
		 |  |  |  +--rw user* [id]
		 |  |  |  |  +--rw id      uint32
		 |  |  |  |  +--rw name?   string
		 |  |  |  +--rw group* [id]
		 |  |  |     +--rw id      uint32
		 |  |  |     +--rw name?   string
		 |  |  +--rw geographic-location
		 |  |     +--rw source
		 |  |     |  +--rw country?   -> /endpoint-groups/location-group/country
		 |  |     |  +--rw region?    -> /endpoint-groups/location-group/region
		 |  |     |  +--rw city?      -> /endpoint-groups/location-group/city
		 |  |     +--rw destination
		 |  |        +--rw country?   -> /endpoint-groups/location-group/country
		 |  |        +--rw region?    -> /endpoint-groups/location-group/region
		 |  |        +--rw city?      -> /endpoint-groups/location-group/city
	 |  |  +--rw threat-feed
		 |  |  +--rw name*   -> /threat-prevention/threat-feed-list/name
     |  +--rw action
	 |  |  +--rw primary-action
		 |	|  +--rw action    identityref
		 |	|  +--rw limit?    decimal64
	 |	|  +--rw secondary-action
         |	|  +--rw log-action?   identityref
	 +--rw endpoint-groups
	 |  +--rw user-group* [name]
	 |  |  +--rw name                              string
	 |     +--rw mac-address*                      yang:mac-address
	 |     +--rw (match-type)
		 |     +--:(ipv4)
		 |     |  +--rw (ipv4-range-or-prefix)?
		 |     |     +--:(prefix)
		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |     |     +--:(range)
		 |     |        +--rw range-ipv4-address* [start end]
		 |     |           +--rw start    inet:ipv4-address-no-zone
		 |     |           +--rw end      inet:ipv4-address-no-zone
		 |     +--:(ipv6)
		 |        +--rw (ipv6-range-or-prefix)?
		 |           +--:(prefix)
		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |           +--:(range)
		 |              +--rw range-ipv6-address* [start end]
		 |                 +--rw start    inet:ipv6-address-no-zone
		 |                 +--rw end      inet:ipv6-address-no-zone
	 |  +--rw device-group* [name]
	 |  |  +--rw name                              string
		|  +--rw (match-type)
		 |  |  +--:(ipv4)
		 |  |  |  +--rw (ipv4-range-or-prefix)?
		 |  |  |     +--:(prefix)
		 |  |  |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |  |  |     +--:(range)
		 |  |  |        +--rw range-ipv4-address* [start end]
		 |  |  |           +--rw start    inet:ipv4-address-no-zone
		 |  |  |           +--rw end      inet:ipv4-address-no-zone
		 |  |  +--:(ipv6)
		 |  |     +--rw (ipv6-range-or-prefix)?
		 |  |        +--:(prefix)
		 |  |        |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |  |        +--:(range)
		 |  |           +--rw range-ipv6-address* [start end]
		 |  |              +--rw start    inet:ipv6-address-no-zone
		 |  |              +--rw end      inet:ipv6-address-no-zone
		|  +--rw application-protocol*             identityref
	 |  +--rw location-group* [country region city]
	 |  |  +--rw country                           string
		|  +--rw region                            string
		|  +--rw city                              string
		|  +--rw (match-type)
		 |     +--:(ipv4)
		 |     |  +--rw (ipv4-range-or-prefix)?
		 |     |     +--:(prefix)
		 |     |     |  +--rw ipv4-prefix*          inet:ipv4-prefix
		 |     |     +--:(range)
		 |     |        +--rw range-ipv4-address* [start end]
		 |     |           +--rw start    inet:ipv4-address-no-zone
		 |     |           +--rw end      inet:ipv4-address-no-zone
		 |     +--:(ipv6)
		 |        +--rw (ipv6-range-or-prefix)?
		 |           +--:(prefix)
		 |           |  +--rw ipv6-prefix*          inet:ipv6-prefix
		 |           +--:(range)
		 |              +--rw range-ipv6-address* [start end]
		 |                 +--rw start    inet:ipv6-address-no-zone
		 |                 +--rw end      inet:ipv6-address-no-zone
	 |  +--rw url-group* [name]
	 |  |  +--rw name    string
	 |	|  +--rw url*    inet:uri
	 |  +--rw voice-group* [name]
	 |  |  +--rw name      string
	 |  |  +--rw sip-id*   inet:uri
	 +--rw threat-prevention
     |  |  +--rw name      string
     |  |  +--rw ioc*      string
     |  |  +--rw format    identityref


    """

    # Combine all elements into the prompt
    prompt = f"""
    You are an expert in XML schema and I2NSF security policies. Convert the following natural language input into an XML security policy compliant with the I2NSF schema. Use the Event-Condition-Action (ECA) format and ensure the XML is valid. Use the three intent-policy examples as formatting and schema-use guidance. Try to add the appropriate header to the XML depending on the needs of the user.

    Three examples for reference:

    Input: {example_input1}
    Output: {example_output1}

    Input: {example_input2}
    Output: {example_output2}

    Input: {example_input3}
    Output: {example_output3}
    Additional Context:
    {ietf_context}

    Now, generate the XML for the following input:
    Input: {policy_text}

    Output:

	Generate only the XML. Do not give additional text.
    """
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an XML schema and I2NSF policy expert."},
            {"role": "user", "content": prompt}
        ]
    )
    
    return response.choices[0].message.content

if __name__ == "__main__":
	# # Example usage
	# # policy_text =  "Permit packets coming from Lima, Peru."
	# # policy_text =  "When the CPU load on the firewall is above 90%, allow only critical management traffic and rate-limit all other flows."
	policy_text =  "Permit access to Youtube, X and Instagram during school hours to all PCs within 128.0.0.0-128.0.0.255 IPv4 ranges."	
	xml_policy = generate_policy(policy_text, model)

	print("Generated XML Policy:")
	print(xml_policy)

	# input_csv = "dataset/intents.csv"       # CSV with 1 column: "intent"
	# output_txt = "generated_policies_baseline.txt"

	# with open(input_csv, newline="", encoding="utf-8") as csvfile:
	# 	reader = csv.DictReader(csvfile)
		
	# 	with open(output_txt, "w", encoding="utf-8") as outfile:
	# 		for row in reader:
	# 			intent = row["intent"].strip()
	# 			if not intent:
	# 				continue
				
	# 			print(f"Generating policy for intent: {intent}")
	# 			xml_policy = generate_policy(intent, model)
				
	# 			# Write XML policy followed by two newlines
	# 			outfile.write(xml_policy + "\n\n\n\n")


	# print(f"All policies generated and saved to {output_txt}")

