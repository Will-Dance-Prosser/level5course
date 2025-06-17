import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import uuid
import random




#build request xml
def generate_request_xml(quote):

    root = ET.Element("GenerateQuoteRequest")
    request_header = ET.SubElement(root, "RequestHeader")
    version = ET.SubElement(request_header, "Version")
    version.text = "2.0"
    request_date_time = ET.SubElement(request_header, "RequestDateTime")
    request_date_time.text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    source = ET.SubElement(request_header, "Source")
    domain = ET.SubElement(source, "Domain")
    domain.text = "Sales"
    line_of_business = ET.SubElement(source, "LineOfBusiness")
    line_of_business.text = "ROS"
    product_list = ET.SubElement(root, "ProductList")
    policy_start_date_time = ET.SubElement(product_list, "PolicyStartDateTime")
    policy_start_date_time.text = quote.start_date.strftime("%Y-%m-%dT%H:%M:%S")
    policy_end_date_time = ET.SubElement(product_list, "PolicyEndDateTime")
    policy_end_date_time.text = (quote.start_date + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S")
    currency = ET.SubElement(product_list, "Currency")
    currency.text = "GBP"
    # Instead of quote.product, use quote.cover_type
    for product in quote.cover_type.split(","):
        product_element = ET.SubElement(product_list, "Product")
        product_code = ET.SubElement(product_element, "ProductCode")
        product_code.text = product
    vehicle_registration_number = ET.SubElement(product_list, "VehicleRegistrationNumber")
    vehicle_registration_number.text = quote.vehicle_registration
    covered_persons = ET.SubElement(product_list, "CoveredPersons")
    covered_persons.text = str(quote.covered_persons)
    customer_details = ET.SubElement(root, "CustomerDetails")
    date_of_birth = ET.SubElement(customer_details, "DateOfBirth")
    date_of_birth.text = quote.date_of_birth.strftime("%Y-%m-%d")
    postcode = ET.SubElement(customer_details, "Postcode")
    postcode.text = quote.postcode

   
    return ET.tostring(root, encoding='unicode')

#request xml format
'''
<GenerateQuoteRequest>
	<RequestHeader>
		<Version></Version>
		<RequestDateTime></RequestDateTime>
		<Source>
			<Domain></Domain>
			<LineOfBusiness></LineOfBusiness>
		</Source>
	</RequestHeader>
	<ProductList>
		<PolicyStartDateTime></PolicyStartDateTime>
		<PolicyEndDateTime></PolicyEndDateTime>
		<Currency></Currency>
		<Product>
			<ProductCode></ProductCode>
		</Product>
		<VehicleRegistrationNumber></VehicleRegistrationNumber>
		<CoveredPersons></CoveredPersons>
	</ProductList>
	<CustomerDetails>		
		<DateOfBirth></DateOfBirth>
		<Postcode></Postcode>
	</CustomerDetails>
</GenerateQuoteRequest>
'''

#build response xml

#response vars

def generate_customer_quote_reference():
    return "AA-"+(str(uuid.uuid4().hex[:8]))  # Generate a random 8-character reference ammends to AA

request_products = {"Roadside":[30.0, 0.0], "Relay":[20.0, 0.0], "HomeStart":[15.0, 0.0], "PartsCover":[25.0, 15.0]} # Products with Arrangement Fees then net rates
tax_percent = 0.12 # 12% tax
profit_margin_range = (0.35, 0.5) # 35% to 50% profit margin
# Generate a random profit margin within the specified range
# Too simulate a realistic scenario, we can use a random profit margin
def generate_profit_margin():
    profit_margin = random.uniform(profit_margin_range[0], profit_margin_range[1])
    return (round(profit_margin, 2))  # Round to 2 decimal places

def generate_taylored_productdict(products):
    product_dict = {}
    for product in products:
        if product in request_products:
            product_dict[product] = request_products[product]
    return product_dict

def generate_response_xml(request_xml):

    # Parse the request XML to extract necessary information
    root_request = ET.fromstring(request_xml)
    product_codes_request_element = root_request.findall(".//ProductCode")
    product_codes_request = []
    for product_code in product_codes_request_element:
        product_code.text = product_code.text.strip()
        product_codes_request.append(product_code.text) # grabs all product codes from the request XML

    covered_persons_request_element = root_request.find(".//CoveredPersons")
    covered_persons_request = int(covered_persons_request_element.text)

    ref = generate_customer_quote_reference()


    product_codes_request_dict = generate_taylored_productdict(product_codes_request)

    #building the response XML
    root = ET.Element("GenerateQuoteResponse")

    # ResponseHeader
    response_header = ET.SubElement(root, "ResponseHeader")
    version = ET.SubElement(response_header, "Version")
    version.text = "2.0"
    response_date_time = ET.SubElement(response_header, "ResponseDateTime")
    response_date_time.text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    source = ET.SubElement(response_header, "Source")
    line_of_business = ET.SubElement(source, "LineOfBusiness")
    line_of_business.text = "ROS"
    app_version = ET.SubElement(source, "ApplicationVersion")
    app_version.text = "1.3"

    # CustomerQuoteReference
    cust_ref = ET.SubElement(root, "CustomerQuoteReference")
    cust_ref.text = ref

    # ProductList
    product_list = ET.SubElement(root, "ProductList")

    # Payment 1 (Annual)
    payment_annual = ET.SubElement(product_list, "Payment")
    payment_type = ET.SubElement(payment_annual, "PaymentType")
    payment_type.text = "Annual"
    currency = ET.SubElement(payment_annual, "Currency")
    currency.text = "GBP"

    

    for prod in product_codes_request_dict:
        commission = request_products[prod][0] * generate_profit_margin()
        commission_tax = round(commission * tax_percent,2)
        net_rate = request_products[prod][1]
        net_rate_Tax = round(net_rate * tax_percent,2)
        tax_total = commission_tax + net_rate_Tax
        
        total = round(commission + net_rate + net_rate_Tax + commission_tax,2)

        arrangement_fee = request_products[prod][0]
        arrangement_fee_tax = round(arrangement_fee * tax_percent,2)
        arrangement_fee_total = round(arrangement_fee + arrangement_fee_tax,2)
        main_total = round(total + arrangement_fee_total,2)


        product_elem = ET.SubElement(payment_annual, "Product")
        product_code = ET.SubElement(product_elem, "ProductCode")
        product_code.text = prod
        price_list = ET.SubElement(product_elem, "PriceList")
        price = ET.SubElement(price_list, "Price")
        price_breakdown = ET.SubElement(price, "PriceBreakdown")
        #CORE PRICE SECTION
        core_price = ET.SubElement(price_breakdown, "CorePrice")
        ET.SubElement(core_price, "netrate").text = str(net_rate)
        ET.SubElement(core_price, "netrateTax").text = str(net_rate_Tax)
        ET.SubElement(core_price, "Commission").text = str(round(commission,2))
        ET.SubElement(core_price, "CommissionTax").text = str(commission_tax)
        ET.SubElement(core_price, "TaxTotal").text = str(tax_total)
        ET.SubElement(core_price, "Total").text = str(total)
        #ARRANGEMENT FEE SECTION
        arrangement_fee1 = ET.SubElement(price_breakdown, "ArrangementFee")
        ET.SubElement(arrangement_fee1, "Fee").text = str(arrangement_fee)
        ET.SubElement(arrangement_fee1, "FeeTax").text = str(arrangement_fee_tax)
        ET.SubElement(arrangement_fee1, "Total").text = str(request_products[prod][0] + (request_products[prod][0]*tax_percent))
        ET.SubElement(price, "ArrangementFeeTotal").text = str(arrangement_fee_total)
        ET.SubElement(price, "TotalLessArrangementFeeTotal").text = str(total)
        ET.SubElement(price, "TotalLessDiscounts").text = str(main_total)
        ET.SubElement(price, "Total").text = str(main_total)

    # TotalPriceBreakdown (Annual)
    total_price_breakdown1 = ET.SubElement(payment_annual, "TotalPriceBreakdown")
    ET.SubElement(total_price_breakdown1, "Total").text = str(main_total)
    ET.SubElement(total_price_breakdown1, "TotalExcludingDiscounts").text = str(main_total)
    ET.SubElement(total_price_breakdown1, "DiscountTotal").text = "0.0"
    ET.SubElement(total_price_breakdown1, "TotalArrangementFee").text = str(arrangement_fee_total)
    ET.SubElement(total_price_breakdown1, "TotalLessArrangementFees").text = str(total)
    ET.SubElement(total_price_breakdown1, "TotalIPT").text = str(tax_total)

    # Payment 2 (Monthly)
    payment_monthly = ET.SubElement(product_list, "Payment")
    payment_type2 = ET.SubElement(payment_monthly, "PaymentType")
    payment_type2.text = "Monthly"
    currency2 = ET.SubElement(payment_monthly, "Currency")
    currency2.text = "GBP"

    for prod in product_codes_request_dict:
        # Use the same logic as annual, but divide all monetary values by 12
        commission = round((request_products[prod][0] * generate_profit_margin()) / 12, 2) 
        commission = commission * 1.1 # Adding a 10% increase to the commission for monthly payments to simulate intrest or additional fees
        commission_tax = round((commission * tax_percent), 2)
        net_rate = request_products[prod][1] / 12
        net_rate_Tax = round(net_rate * tax_percent, 2)
        tax_total = commission_tax + net_rate_Tax

        total = round(commission + net_rate + net_rate_Tax + commission_tax, 2)

        arrangement_fee = round(request_products[prod][0] / 12,2)
        arrangement_fee_tax = round(arrangement_fee * tax_percent, 2)
        arrangement_fee_total = round(arrangement_fee + arrangement_fee_tax, 2)
        main_total = round(total + arrangement_fee_total, 2)

        product_elem = ET.SubElement(payment_monthly, "Product")
        product_code = ET.SubElement(product_elem, "ProductCode")
        product_code.text = prod
        price_list = ET.SubElement(product_elem, "PriceList")
        price = ET.SubElement(price_list, "Price")
        price_breakdown = ET.SubElement(price, "PriceBreakdown")
        # CORE PRICE SECTION
        core_price = ET.SubElement(price_breakdown, "CorePrice")
        ET.SubElement(core_price, "netrate").text = str(round(net_rate, 2))
        ET.SubElement(core_price, "netrateTax").text = str(net_rate_Tax)
        ET.SubElement(core_price, "Commission").text = str(commission)
        ET.SubElement(core_price, "CommissionTax").text = str(commission_tax)
        ET.SubElement(core_price, "TaxTotal").text = str(tax_total)
        ET.SubElement(core_price, "Total").text = str(total)
        # ARRANGEMENT FEE SECTION
        arrangement_fee1 = ET.SubElement(price_breakdown, "ArrangementFee")
        ET.SubElement(arrangement_fee1, "Fee").text = str(arrangement_fee)
        ET.SubElement(arrangement_fee1, "FeeTax").text = str(arrangement_fee_tax)
        ET.SubElement(arrangement_fee1, "Total").text = str(arrangement_fee_total)
        ET.SubElement(price, "ArrangementFeeTotal").text = str(arrangement_fee_total)
        ET.SubElement(price, "TotalLessArrangementFeeTotal").text = str(total)
        ET.SubElement(price, "TotalLessDiscounts").text = str(main_total)
        ET.SubElement(price, "Total").text = str(main_total)

    # TotalPriceBreakdown (Monthly)
    total_price_breakdown2 = ET.SubElement(payment_monthly, "TotalPriceBreakdown")
    ET.SubElement(total_price_breakdown2, "Total").text = str(main_total)
    ET.SubElement(total_price_breakdown2, "TotalExcludingDiscounts").text = str(main_total)
    ET.SubElement(total_price_breakdown2, "DiscountTotal").text = "0.0"
    ET.SubElement(total_price_breakdown2, "TotalArrangementFee").text = str(arrangement_fee_total)
    ET.SubElement(total_price_breakdown2, "TotalLessArrangementFees").text = str(total)
    ET.SubElement(total_price_breakdown2, "TotalIPT").text = str(tax_total)

    # QuoteExpiryDate
    expiry = ET.SubElement(root, "QuoteExpiryDate")
    expiry.text = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")

    return (ET.tostring(root, encoding='unicode'))


#Response XML Parser
def parse_response_xml(Response_XML):
    root = ET.fromstring(Response_XML)
    response_header = root.find("ResponseHeader")
    response_date_time = response_header.find("ResponseDateTime").text
    quote_reference = root.find("CustomerQuoteReference").text


    response_details = []
    annual_details = {
        'ref': quote_reference,
        'payment_type': "Annual",
        'response_date_time': response_date_time,
        'products': [],
        'exipiry_date': root.find("QuoteExpiryDate").text,
        'overall_total': None
    }
    monthly_details = {
        'ref': quote_reference,
        'payment_type': "Monthly",
        'response_date_time': response_date_time,
        'products': [],
        'exipiry_date': root.find("QuoteExpiryDate").text,
        'overall_total': None
    }

    for payment in root.findall(".//Payment"):
        payment_type = payment.find("PaymentType").text
        for product in payment.findall("Product"):
            product_code = product.find("ProductCode").text
            price_elem = product.find(".//Price")
            total = price_elem.find("Total").text if price_elem is not None else None
            if total is not None:
                try:
                    total = f"{float(total):.2f}"
                except Exception:
                    pass
            product_info = {
                'product_code': product_code,
                'total': total
            }
            if payment_type == "Annual":
                annual_details['products'].append(product_info)
            elif payment_type == "Monthly":
                monthly_details['products'].append(product_info)
    
    # Calculate overall total for both annual and monthly
    annual_total = sum(float(p['total']) for p in annual_details['products'] if p['total'] is not None)
    monthly_total = sum(float(p['total']) for p in monthly_details['products'] if p['total'] is not None)
    annual_details['overall_total'] = round(annual_total, 2)
    monthly_details['overall_total'] = round(monthly_total, 2)

    response_details.append(annual_details)
    response_details.append(monthly_details)
    return response_details


    

        


if __name__ == "__main__":
    quote = MockQuote()
    #request_xml = generate_request_xml(quote)
    #print(request_xml)
    response_xml = generate_response_xml()
    print(response_xml)
