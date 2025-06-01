import phonenumbers, sys
from phonenumbers import timezone, carrier, geocoder

def get_info():

    try:
        phone_number = sys.argv[1] # ادخل الرقم مع رمز البلد

    except IndexError:
        print("ex: python main.py +254845484787254")
        return
    
    number = phonenumbers.parse(phone_number) # تمرير الرقم الي قاعدة البيانات
    possible = phonenumbers.is_possible_number(number) # التأكد من انه رقم حقيقي
    valid = phonenumbers.is_valid_number(number) # التأكد من فعالية الرقم
    
    Carrier = carrier.name_for_number(number, 'en') # Vodafone
    Region = geocoder.description_for_number(number, 'en') # France
    timeZone = timezone.time_zones_for_number(number) # ('Europe, France')

    data_list = {
        "is it exists": possible,
        "valid" : valid,
        "company name": Carrier,
        "country name": Region,
        "timezone": timeZone
    }
  
    print(data_list)

    
get_info()
