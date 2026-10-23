from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
otx = OTXv2("808673fb9a3d3200c19ffc54779054fd2e97462aead3dc66039e3fdeb85a007e")
# Get all the indicators associated with a pulse
indicators = otx.get_pulse_indicators("6ab0801b8e4c7669fbb5996d")
for indicator in indicators:
    print(indicator["indicator"] + indicator["type"])
# Get everything OTX knows about google.com
otx.get_indicator_details_full(IndicatorTypes.DOMAIN, "google.com")