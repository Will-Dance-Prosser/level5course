from .models import Quote, QuoteXML
from .utils import xml_parser, find_field_value
from sqlalchemy import func

CANONICAL_ORDER = ["Roadside", "Relay", "HomeStart", "PartsCover"]

class SearchService:
    def __init__(self, db):
        self.db = db

    def ordered_products(self, products):
        return [p for p in CANONICAL_ORDER if p in products]

    def filter_quotes(self, customer_name, vehicle_reg, postcode, date_of_birth, products):
        query = self.db.session.query(Quote)
        if customer_name:
            query = query.filter(func.upper(Quote.customer_name) == customer_name.upper())
        if vehicle_reg:
            query = query.filter(func.upper(Quote.vehicle_registration) == vehicle_reg.upper())
        if postcode:
            query = query.filter(func.upper(Quote.postcode) == postcode.upper())
        if date_of_birth:
            query = query.filter(Quote.date_of_birth == date_of_birth)
        if products:
            products_str = ",".join(self.ordered_products(products))
            query = query.filter(Quote.cover_type == products_str)
        return query.all()

    def product_matches(self, product, commission, arrangment_fee, net):
        core_price_section = (
            product.get("PriceList", {})
            .get("Price", {})
            .get("PriceBreakdown", {})
            .get("CorePrice", {})
        )
        if commission and not find_field_value(core_price_section, "Commission", commission):
            return False
        if arrangment_fee and not find_field_value(core_price_section, "Fee", arrangment_fee):
            return False
        if net and not find_field_value(core_price_section, "netrate", net):
            return False
        return True

    def xml_matches(self, xml_content, payment_type, commission, arrangment_fee, net):
        parsed_xml = xml_parser(xml_content)
        product_list = parsed_xml.get("GenerateQuoteResponse", {}).get("ProductList", {})
        payments = product_list.get("Payment", [])
        if isinstance(payments, dict):
            payments = [payments]
        for payment in payments:
            if payment_type and payment.get("PaymentType") != payment_type:
                continue
            products_list = payment.get("Product", [])
            if isinstance(products_list, dict):
                products_list = [products_list]
            for product in products_list:
                if self.product_matches(product, commission, arrangment_fee, net):
                    return True
        return not (commission or arrangment_fee or net)  # If no criteria, match all

    def search_quotes(
        self,
        customer_name=None,
        vehicle_reg=None,
        postcode=None,
        date_of_birth=None,
        products=None,
        payment_type=None,
        commission=None,
        arrangment_fee=None,
        net=None
    ):
        quotes = self.filter_quotes(customer_name, vehicle_reg, postcode, date_of_birth, products)
        quote_ids = [quote.quote_id for quote in quotes]
        if not quote_ids:
            return []
        xmls = self.db.session.query(QuoteXML).filter(
            QuoteXML.quote_id.in_(quote_ids),
            QuoteXML.xml_type == 'response'
        ).all()
        matching_ids = [
            xml.quote_id for xml in xmls
            if self.xml_matches(xml.xml_content, payment_type, commission, arrangment_fee, net)
        ]
        return [quote for quote in quotes if quote.quote_id in matching_ids]