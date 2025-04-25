

//SHIZONET & CONFIGASSIST DEMO PROJECT


//We use this to initialize WiFi and the webconfig here, but you can manually initialize WLAN yourself too.
#include <shz_config.h>

//From arduino library
#include <shizonet.h>

//Initialize a receiving shizonet end node
shznet_client client;

//Used for webconfig
shz_config conf;

//debug output
bool          debug_output = false;

template<class T> void sprint(T prnt)
{
  if(!debug_output) return;
  Serial.print(prnt);
}
template<class T> void sprintln(T prnt)
{
  if(!debug_output) return;
  Serial.println(prnt);
}

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);

  //------------------------
  //CONFIG ASSIST
  //------------------------
  //Look at config assist for how to use this...
  //shizonet itself does not handle the network
  //initialization, it just opens an UDP port.
  //You can initialize the wifi / eth stuff yourself here
  //but config assist is an easy way to do that.
  static const char* VARIABLES_DEF_YAML PROGMEM = R"~(
  )~";

  //Initializ rest of webconfig stuff...
  conf.on_change([](String& key)
  {
    if(key == "debug")
    {
      debug_output = conf.get_int("debug");
      sprintln("debug output changed.");
    }
  });

  debug_output = conf.get_int("debug");

  //Initializes WLAN eth etc...
  conf.init("ESP32TEST", VARIABLES_DEF_YAML);


  //------------------------
  //SHIZONET
  //------------------------

  //Initialize network node
  client.init("ESP32");
  
  //------------------------
  //SHIZONET - ARTNET
  //------------------------
  //Do not show LEDS on this callback, use it to set data
  client.setArtDmxCallback([](uint16_t universe, uint16_t length, uint8_t sequence, uint8_t* data, shznet_ip remoteIP)
  {
    //Receive a DMX universe frame and do something with it
    //This is the place to memcpy LED data into the LED buffer for example
  });

  //Show LEDS, update frame whatever
  client.setArtFrameCallback([]()
  {
    //This function gets called after 
    //ALL currently streamed universes have been received
    //Use this to call FastLED.show for example
  });

  //------------------------
  //SHIZONET - FUNCTIONS
  //------------------------

  //### SIMPLE
  //The most basic function to add a shizonet command
  //To receive data only
  client.add_command("simple_command", [](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
  {
    Serial.printf("Received command from: %s\n", ip.str().c_str());
    Serial.printf("Data size: %llu\n", size);
    Serial.printf("Data: %s\n", (char*)data);
  });

  //### RELIABLE
  //add a advanced shizonet command which can also respond (default)
  //NOTE: this is just a demonstration! Use add_command_respond to actually send data back and forth.
  client.add_command("test_reliable", [](shznet_command& cmd)
  {
    Serial.printf("Received command from: %s (%s)\n", cmd.ip().str().c_str(), cmd.mac().str().c_str());
    Serial.printf("Data size: %llu\n", cmd.size());
    Serial.printf("Data: %s\n", (char*)cmd.data());

    //Send something to the sender
    auto dev = cmd.device();
    
    std::string response = "Hello reliable!";

    dev->send_reliable("test_reliable_respond",   /*The command for the sender*/
            (byte*)response.c_str(),              /*The data to be sent*/
            response.length(),                    /*The size of the data*/
            SHZNET_PKT_FMT_STRING,                /*The format of the data*/
            0,                                    /*Sequential or parallel send (When set true, it will be sent sequential like a queue, if set to false it will send it instantly and parallel to all currently open orders*/
            1000 * 10                             /*Timeout for the command, set to 0 for no timeout*/
          );
  });

  //### UNRELIABLE
  //Unreliable data transmission (streaming)
  client.add_command("test_unreliable", [](shznet_command& cmd)
  {
    Serial.printf("Received command from: %s (%s)\n", cmd.ip().str().c_str(), cmd.mac().str().c_str());
    Serial.printf("Data size: %llu\n", cmd.size());
    Serial.printf("Data: %s\n", (char*)cmd.data());

    //Send something to the sender
    auto dev = cmd.device();

    std::string response = "Hello reliable!";

    dev->send_unreliable("test_unreliable_respond",   /*The command for the sender*/
            (byte*)response.c_str(),                /*The data to be sent*/
            response.length(),                    /*The size of the data*/
            SHZNET_PKT_FMT_STRING                 /*The format of the data*/
          );
  });


  //##RESPOND COMMANDS
  client.add_command_respond("test_respond", [](std::shared_ptr<shznet_responder> responder)
  {
    auto dev = responder->device();
    Serial.printf("Received command from: %s (%s)\n", dev->get_ip().str().c_str(), dev->get_mac().str().c_str());
    Serial.printf("Data size: %llu\n", responder->size());
    Serial.printf("Data: %s\n", (char*)responder->data());

    //Send the data back...
    responder->respond(responder->data(), responder->size(), responder->format());
  });

  //MORE ADVANCED FEATURES, SENDING DIFFERENT DATA TYPES ETC...
  //TODO...
  //Basic example of making a "poll" sensor command with a key value parameter list
  client.add_command_respond("sensor_example", [](std::shared_ptr<shznet_responder> responder)
  {
    //check if the incoming data is a key-value map
    if(responder->format() != SHZNET_PKT_FMT_KEY_VALUE)
    {
      Serial.println("Received invalid format!");
      return;
    }

    shznet_kv_reader kvr(responder->data(), responder->size());

    Serial.printf("Sensor name: %s\n", kvr.read_string("sensor_name"));
    Serial.printf("Sensor index: %i\n", kvr.read_int32("sensor_index"));

    //Respond with test data:
    shznet_kv_writer kvw;
    kvw.add_string("State", "success");
    kvw.add_int32("value1", 1337);
    kvw.add_float32("value2", 13.37);
    responder->respond(kvw);
  });

  Serial.print("Mem: ");
  Serial.println(ESP.getFreeHeap());
}

void loop() {
  //Dont forget to update the client regulary!
  client.update();
  conf.update();
}
