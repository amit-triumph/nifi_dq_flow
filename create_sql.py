import sys
import json
import re


def date_diff_check(rule,final_json):
    try:
        table_name = rule.get('table_name')
        condition = rule.get('condition')
        column_name = rule.get('column_name')
        pk_column = rule.get('pk_column')
        pk_columns = [col.strip() for col in pk_column.split(",")]
        pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"

        right_date = column_name.split(",")[0]
        left_date = column_name.split(",")[1]

        # Regex to split condition into left expression, operator, and right expression
        pattern = r"(.+?)\s*(<=|>=|<|>)\s*(.+)"
        match = re.match(pattern, condition)

        if not match:
            raise ValueError(f"Invalid condition format: {condition}")

        operator = match.group(2).strip()
        right_side = match.group(3).strip()

    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)
    else:
        return (
                    f"SELECT '{table_name}' AS table_name, {pk_column}, "
                    f"{pk_concat} AS concatenated_pk_columns "
                    f"FROM {table_name} "
                    f"WHERE {right_date}+INTERVAL '{right_side}' {operator} {left_date};"
                )

def custom_where_check(rule,final_json):
    try:
        table_name = rule.get('table_name')
        condition = rule.get('condition')
        column_name = rule.get('column_name')
        pk_column = rule.get('pk_column')
        pk_columns = [col.strip() for col in pk_column.split(",")]
        pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"

    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)
    else:
        return f"SELECT '{table_name}' table_name,{pk_column},{pk_concat} concatenated_pk_columns FROM {table_name} WHERE {condition};"

def valid_values_check(rule,final_json):
    try:
        table_name = rule.get('table_name')
        condition = rule.get('condition')
        column_name = rule.get('column_name')
        pk_column = rule.get('pk_column')
        pk_columns = [col.strip() for col in pk_column.split(",")]
        pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"
        valid_values = []
        for col in condition.split(','):
            valid_values.append(f"'{col}'")

        valid_values = ",".join(valid_values)

    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)
    else:
        return f"SELECT '{table_name}' table_name,{pk_column},{pk_concat} concatenated_pk_columns FROM {table_name} WHERE {column_name} NOT IN ({valid_values})"

def pk_check(rule,final_json):
    try:
        columns = rule.get('column_name')
        pk_column = rule.get('pk_column')
        pk_columns = [col.strip() for col in pk_column.split(",")]
        pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"
        table_name = rule.get('table_name')
        # return f"""
        # SELECT {columns}, COUNT(*) as cnt FROM {rule['table_name']} GROUP BY {columns} HAVING COUNT(*) > 1;
        # """.strip()
    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)
    else:
        return f"""
        SELECT '{table_name}' table_name,
        {columns}, 
        {pk_concat} concatenated_pk_columns FROM 
        (SELECT {columns},
            COUNT(*) OVER(PARTITION BY {columns}) AS cnt 
        FROM {rule['table_name']}) AS count_records 
            WHERE cnt > 1;
        """.strip()

def not_null_check(rule,final_json):
    try:
        column = rule.get('column_name')
        pk_column = rule.get('pk_column')
        pk_columns = [col.strip() for col in pk_column.split(",")]
        pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"
        table_name = rule.get("table_name")
    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)
    else:
        return f"SELECT '{table_name}' table_name, {pk_column}, {pk_concat} concatenated_pk_columns FROM {rule['table_name']} WHERE {column} is null;"

def unique_check(rule,final_json):
    try:
        column = rule.get('column_name')
        pk_column = rule.get('pk_column')
        pk_columns = [col.strip() for col in pk_column.split(",")]
        pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"
        table_name = rule.get("table_name")

    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)
    else:
    # return f"""SELECT {pk_column}, COUNT(*) as cnt FROM {rule['table_name']} GROUP BY {column} HAVING COUNT(*) > 1;
    # """.strip()
        return f"""SELECT '{table_name}' table_name, {pk_column}, {pk_concat} concatenated_pk_columns FROM {rule['table_name']} GROUP BY {column} HAVING COUNT(*) > 1;
        """.strip()

def fk_check(rule,final_json):
    try:
        condition = rule.get('condition')
        child_table = rule.get('table_name')
        pk_column = rule.get('pk_column')
        table_name = rule.get('table_name')
        # pk_columns = [col.strip() for col in pk_column.split(",")]
        # pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"

        # Extract parent table name from condition
        # e.g., 'acct.acct_type_id = acct_type.acct_type_id'
        parent_table = condition.split("=")[1].strip().split(".")[0]

        # Extract all parent-side columns from condition (supports multiple conditions)
        parent_columns = []
        conditions = condition.split(" and ")
        for cond in conditions:
            parts = cond.split("=")
            if len(parts) == 2:
                right = parts[1].strip()
                if "." in right:
                    parent_columns.append(right)

        # Build IS NULL conditions on parent columns
        null_checks = " OR ".join([f"{col} IS NULL" for col in parent_columns])

        pk_columns = ",".join([f"{child_table}.{col}" for col in pk_column.split(",")])
        pk_concat  = f"concat_ws('_',{pk_columns})"

        # Build final SQL
        sql = f"""  
        SELECT '{table_name}' table_name, {pk_columns}, {pk_concat} concatenated_pk_columns FROM {child_table} LEFT JOIN {parent_table} ON {condition} WHERE {null_checks};
        """.strip()
    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)
    else:
        return sql
def default_check(rule):
    table_name = rule.get('table_name')
    condition = rule.get('condition')
    pk_columns = [col.strip() for col in pk_column.split(",")]
    pk_concat  = f"concat_ws('_',{', '.join(pk_columns)})"
    return f"SELECT '{table_name}' table_name,{rule.get('pk_column')},{pk_concat} concatenated_pk_columns FROM {rule.get('table_name')} WHERE {rule.get('column_name')} = {condition};"

# Rule dispatcher
rule_dispatcher = {
    'primary_key_check':pk_check,
    'foreign_key_check':fk_check,
    'uniqueness_check': unique_check,
    'default_check': default_check,
    # 'pattern_check': pattern_check,
    'not_null_checks': not_null_check,
    # 'range_check': range_check,
    'valid_values_ckeck': valid_values_check,
    'custom_where_check': custom_where_check,
    'date_diff_check': date_diff_check
}

def main(input_json):
    final_json = {}
    # input_json = sys.stdin.read()
    try:
        # rule = input_json
        rule = json.loads(input_json)
        final_json['rule_id'] = rule.get('rule_id')
        final_json['rule_name'] = rule.get('rule_name')
        final_json['validation_type'] = rule.get('validation_type')
        final_json['validation_grp'] = rule.get('validation_grp')
        final_json['validation_rule'] = rule.get('validation_rule')
        final_json['condition'] = rule.get('condition')
        final_json['table_name'] = rule.get('table_name')
        final_json['total_record_in_table'] = rule.get('total_record_in_table')
        final_json['pk_column'] = rule.get('pk_column')
        final_json['today'] = rule.get('today')

        # rule = input_json
        rule_type = rule.get("validation_rule")

        if rule_type not in rule_dispatcher:
            # print(f"-- Unsupported rule: {rule_type}")
            final_json['query_generation_status'] = "Unsupported rule"
            print(json.dumps(final_json))
            sys.exit(1)

        sql = rule_dispatcher[rule_type](rule,final_json)

        final_json['sql_query'] = sql
        final_json['query_generation_status'] = "ok"
        print(json.dumps(final_json))

    except Exception as e:
        final_json['query_generation_status'] = e
        print(json.dumps(final_json))
        sys.stderr.write(f"Error processing rule: {e}")
        sys.exit(1)

if __name__ == "__main__":
    null = 'null'
    false = 'false'
    true = 'true'
    input_json = sys.stdin.read()
    # input_json = {"rule_id":118,"rule_name":"BusinessValidation_Validity_acct_status_valid_values_ckeck_[]","connection_id":1,"table_name":"acct","validation_type":"BusinessValidation","validation_grp":"Validity","column_name":"acct_status","validation_rule":"valid_values_ckeck","condition":"Active,Closed","column_description":"Activity based account status","rule_description":null,"pk_column":"acct_group,acct_nbr","row_count":21}
    main(input_json)
