import streamlit as st
import pandas as pd
import plotly.express as px
import hashlib
from pymongo import MongoClient

# Sample user data for login (replace with actual user authentication system)
USER_CREDENTIALS = {
    "admin": "admin123",  # Replace with actual password hash in real-world applications
}

# Function to hash passwords (for security purposes)
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Function to validate login credentials
def validate_login(username, password):
    if username in USER_CREDENTIALS and hash_password(password) == hash_password(USER_CREDENTIALS[username]):
        return True
    return False

# Function to establish MongoDB connection
def get_db_connection():
    client = MongoClient("mongodb+srv://Balaji_1:Balaji646@cluster0.xktlv.mongodb.net/")  # Replace with your MongoDB URI
    db = client['Policy_Data']  # Replace with your database name
    return db

# Function to fetch distinct values from MongoDB collection for dropdowns
def fetch_distinct_values(field_name):
    db = get_db_connection()
    collection = db['NOP_DATA']  # Replace with your collection name
    distinct_values = collection.distinct(field_name)
    return distinct_values

# Function to fetch filtered data from MongoDB based on selected filters
def fetch_filtered_data(insurance_branch=None, company_name=None, insurance_type=None):
    db = get_db_connection()
    if db is not None:
        collection = db['NOP_DATA']  # Replace with your collection name

        query = {}

        if insurance_branch:
            query['INSURANCEBRANCH'] = insurance_branch
        if company_name:
            query['companyname'] = company_name
        if insurance_type:
            query['INSURANCETYPE'] = insurance_type


        try:
            # Fetch data
             # Handle invalid dates by converting them to NaT (Not a Time)
            data = collection.find(query)
            df = pd.DataFrame(list(data))  # Convert to DataFrame for easy handling
            if 'POLICYISSUEDATE' in df.columns:
                df['POLICYISSUEDATE'] = pd.to_datetime(df['POLICYISSUEDATE'],errors='coerce')
            # Drop the '_id' column (ObjectId) from the DataFrame
            if '_id' in df.columns:
                df = df.drop(columns=['_id'])

            return df
        except Exception as e:
            st.error(f"Error fetching data: {e}")
            return pd.DataFrame()
    return pd.DataFrame()

# Function to perform aggregation and generate graphs (Company-wise and Product-wise)
def generate_analysis(df, filter_type):
    # Aggregating data based on filter type
    if filter_type == 'Insurance Branch':
        # Branch-wise analysis: Show company and insurance type
        branch_wise_data = df.groupby('INSURANCEBRANCH').size().reset_index(name='Count')
        company_wise_data = df.groupby('companyname').size().reset_index(name='Count')
        product_wise_data = df.groupby('INSURANCETYPE').size().reset_index(name='Count')

        # Display branch-wise data in a table
        st.subheader('Insurance Branch-wise Data')
        st.write(branch_wise_data)

        # Plotting company-wise pie chart
        st.subheader('Company-wise Analysis')
        company_fig = px.pie(
            company_wise_data,
            names='companyname',
            values='Count',
            title='Company-wise Count of Policies',
            labels={'companyname': 'Company', 'Count': 'Policy Count'},
            color='companyname',
            color_discrete_sequence=px.colors.qualitative.Set3,
            hole=0.3
        )
        st.plotly_chart(company_fig)

        # Plotting product-wise pie chart
        st.subheader('Product-wise Analysis')
        product_fig = px.pie(
            product_wise_data,
            names='INSURANCETYPE',
            values='Count',
            title='Product-wise Count of Policies',
            labels={'INSURANCETYPE': 'Insurance Type', 'Count': 'Policy Count'},
            color='INSURANCETYPE',
            color_discrete_sequence=px.colors.qualitative.Set3,
            hole=0.3
        )
        st.plotly_chart(product_fig)

    elif filter_type == 'Company':
        # Company-wise analysis: Show branch and insurance type
        company_wise_data = df.groupby('companyname').size().reset_index(name='Count')
        branch_wise_data = df.groupby('INSURANCEBRANCH').size().reset_index(name='Count')
        product_wise_data = df.groupby('INSURANCETYPE').size().reset_index(name='Count')

        # Display company-wise data in a table
        st.subheader('Company-wise Data')
        st.write(company_wise_data)

        # Plotting branch-wise pie chart
        st.subheader('Insurance Branch-wise Analysis')
        branch_fig = px.pie(
            branch_wise_data,
            names='INSURANCEBRANCH',
            values='Count',
            title='Insurance Branch-wise Count of Policies',
            labels={'INSURANCEBRANCH': 'Branch', 'Count': 'Policy Count'},
            color='INSURANCEBRANCH',
            color_discrete_sequence=px.colors.qualitative.Set3,
            hole=0.3
        )
        st.plotly_chart(branch_fig)

        # Plotting product-wise pie chart
        st.subheader('Product-wise Analysis')
        product_fig = px.pie(
            product_wise_data,
            names='INSURANCETYPE',
            values='Count',
            title='Product-wise Count of Policies',
            labels={'INSURANCETYPE': 'Insurance Type', 'Count': 'Policy Count'},
            color='INSURANCETYPE',
            color_discrete_sequence=px.colors.qualitative.Set3,
            hole=0.3
        )
        st.plotly_chart(product_fig)

    elif filter_type == 'Insurance Type':
        # Insurance type-wise analysis: Show branch and company
        product_wise_data = df.groupby('INSURANCETYPE').size().reset_index(name='Count')
        branch_wise_data = df.groupby('INSURANCEBRANCH').size().reset_index(name='Count')
        company_wise_data = df.groupby('companyname').size().reset_index(name='Count')

        # Display product-wise data in a table
        st.subheader('Product-wise Data')
        st.write(product_wise_data)

        # Plotting branch-wise pie chart
        st.subheader('Insurance Branch-wise Analysis')
        branch_fig = px.pie(
            branch_wise_data,
            names='INSURANCEBRANCH',
            values='Count',
            title='Insurance Branch-wise Count of Policies',
            labels={'INSURANCEBRANCH': 'Branch', 'Count': 'Policy Count'},
            color='INSURANCEBRANCH',
            color_discrete_sequence=px.colors.qualitative.Set3,
            hole=0.3
        )
        st.plotly_chart(branch_fig)

        # Plotting company-wise pie chart
        st.subheader('Company-wise Analysis')
        company_fig = px.pie(
            company_wise_data,
            names='companyname',
            values='Count',
            title='Company-wise Count of Policies',
            labels={'companyname': 'Company', 'Count': 'Policy Count'},
            color='companyname',
            color_discrete_sequence=px.colors.qualitative.Set3,
            hole=0.3
        )
        st.plotly_chart(company_fig)
def fetch_all_data():
    db = get_db_connection()
    if db is not None:
        collection = db['NOP_DATA']  # Replace with your collection name

        try:
            # Fetch all raw data
            data = collection.find()
            df = pd.DataFrame(list(data))  # Convert to DataFrame for easy handling
            if 'POLICYISSUEDATE' in df.columns:
                df['POLICYISSUEDATE'] = pd.to_datetime(df['POLICYISSUEDATE'],errors='coerce')
            # Drop the '_id' column (ObjectId) from the DataFrame
            if '_id' in df.columns:
                df = df.drop(columns=['_id'])

            return df
        except Exception as e:
            st.error(f"Error fetching raw data: {e}")
            return pd.DataFrame()
    return pd.DataFrame()

# Main app logic
def main():
    # Check if the user is logged in
    if 'logged_in' in st.session_state and st.session_state.logged_in:
        # Show the dashboard after login
        st.title('Insurance Data Analysis Dashboard')

        # Filter options for view analysis
        filter_type = st.sidebar.selectbox('Select Filter Type', ['Insurance Branch', 'Company', 'Insurance Type'])

        # Fetch dynamic dropdown lists from MongoDB
        if filter_type == 'Insurance Branch':
            insurance_branches = fetch_distinct_values('INSURANCEBRANCH')
            insurance_branch = st.sidebar.selectbox('Select Insurance Branch', insurance_branches)
            company_name = None
            insurance_type = None
        elif filter_type == 'Company':
            companies = fetch_distinct_values('companyname')
            company_name = st.sidebar.selectbox('Select Company', companies)
            insurance_branch = None
            insurance_type = None
        else:  # Insurance Type
            insurance_types = fetch_distinct_values('INSURANCETYPE')
            insurance_type = st.sidebar.selectbox('Select Insurance Type', insurance_types)
            insurance_branch = None
            company_name = None

        # Buttons for data or analysis view
        st.subheader("Select View Option")
        view_option = st.sidebar.radio('Select View', ['View Raw Data', 'View Analysis'])

        # Fetch and display the data based on the selected view
        if view_option == 'View Raw Data':
            # Fetch raw data based on filters
            df_filtered = fetch_filtered_data(
                insurance_branch=insurance_branch,
                company_name=company_name,
                insurance_type=insurance_type
            )

            if df_filtered.empty:
                st.warning('No data found for the selected criteria.')
            else:
                st.subheader('Filtered Raw Data')
                st.write(df_filtered)  # Display filtered raw data

        elif view_option == 'View Analysis':
            # Fetch filtered data for analysis
            df_filtered = fetch_filtered_data(
                insurance_branch=insurance_branch,
                company_name=company_name,
                insurance_type=insurance_type
            )

            if df_filtered.empty:
                st.warning('No data found for the selected criteria.')
            else:
                # Show the analysis
                generate_analysis(df_filtered, filter_type)  # Show analysis based on filter type

        # Large button for "View All Data"
        if st.button("View All Data", key="all_data_button"):
            # Fetch all raw data (unfiltered)
            df_all = fetch_all_data()
            if df_all.empty:
                st.warning('No data available in the database.')
            else:
                st.subheader('All Data (Unfiltered)')
                st.write(df_all)  # Display all raw data
        st.markdown("""
                            If you like this app, please consider Buying me a Coffee ☕
                        """)
    else:
        # Show login page first if not logged in
        st.sidebar.title('Login')
        username = st.sidebar.text_input('Username')
        password = st.sidebar.text_input('Password', type='password')

        if st.sidebar.button('Login'):
            if validate_login(username, password):
                st.session_state.logged_in = True
                st.success('Login Successful!')
            else:
                st.session_state.logged_in = False
                st.error('Invalid Credentials')

if __name__ == "__main__":
    main()
