module Bamboozled
  module API
    class Tabular < Base
      def add_row(table_name: nil, details: nil, employee_id: nil)
        url = "employees/#{employee_id}/tables/#{table_name}"
        row_data = generate_xml(details)
        options = { body: row_data }

        request(:post, url, options)
      end

      def update_row(table_name: nil, details: nil, employee_id: nil, row_id: nil)
        url = "employees/#{employee_id}/tables/#{table_name}/#{row_id}"
        row_data = generate_xml(details)
        options = { body: row_data }

        request(:post, url, options)
      end

      def get_table(table_name: nil, employee_id: nil)
        url = "employees/#{employee_id}/tables/#{table_name}"

        request(:get, url)
      end

      private

      def generate_xml(details)
        "".tap do |xml|
          xml << "<row>"
          details.each { |k, v| xml << "<field id='#{k}'>#{v}</field>" }
          xml << "</row>"
        end
      end
    end
  end
end
