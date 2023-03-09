// MIT License
//
// Copyright (c) 2023 Lack
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package adapter

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"go.etcd.io/etcd/client/v3"
	"gorm.io/gorm"
)

var Prefix = "/rbac"

// EtcdAdapter represents the Gorm adapter for policy storage.
type EtcdAdapter struct {
	tablePrefix string
	tableName   string
	conn        *clientv3.Client
	isFiltered  bool
}

// NewEtcdAdapter is the constructor for Adapter.
func NewEtcdAdapter(conn *clientv3.Client) (*EtcdAdapter, error) {
	ctx := context.Background()
	_, err := conn.MemberList(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect etcd: %v", err)
	}

	a := &EtcdAdapter{tablePrefix: Prefix, conn: conn}
	a.tableName = (&Rule{}).TableName()

	return a, nil
}

// getTableInstance return the dynamic table name
func (a *EtcdAdapter) getTableInstance() string {
	return path.Join(a.tablePrefix, a.tableName)
}

func (a *EtcdAdapter) getFullTableName() string {
	if a.tablePrefix != "" {
		return a.tablePrefix + "/" + a.tableName
	}
	return a.tableName
}

func (a *EtcdAdapter) ruleTable() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		tableName := a.getFullTableName()
		return db.Table(tableName)
	}
}

func (a *EtcdAdapter) dropTable() error {

	t := a.getFullTableName()
	_, err := a.conn.Delete(context.TODO(), t, clientv3.WithPrefix())
	if err != nil {
		return err
	}

	return nil
}

// LoadPolicy loads policy from database.
func (a *EtcdAdapter) LoadPolicy(model model.Model) error {

	ctx := context.TODO()
	key := a.getFullTableName()
	options := []clientv3.OpOption{clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend)}

	rsp, err := a.conn.Get(ctx, key, options...)
	if err != nil {
		return err
	}

	lines := make([][]string, 0)
	for _, kv := range rsp.Kvs {
		line := strings.TrimPrefix(string(kv.Key), key+"/")
		lines = append(lines, strings.Split(line, "/"))
	}

	err = a.Preview(&lines, model)
	if err != nil {
		return err
	}
	for _, line := range lines {
		err := loadPolicyLine(a.lineToRule(strings.Join(line, "/")), model)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *EtcdAdapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	var lines []Rule

	batchFilter := BatchFilter{
		filters: []Filter{},
	}
	switch filterValue := filter.(type) {
	case Filter:
		batchFilter.filters = []Filter{filterValue}
	case *Filter:
		batchFilter.filters = []Filter{*filterValue}
	case []Filter:
		batchFilter.filters = filterValue
	case BatchFilter:
		batchFilter = filterValue
	case *BatchFilter:
		batchFilter = *filterValue
	default:
		return errors.New("unsupported filter type")
	}

	ctx := context.TODO()
	for _, f := range batchFilter.filters {
		prefix := a.filterQuery(f)
		rsp, err := a.conn.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend))
		if err != nil {
			return err
		}

		for _, kv := range rsp.Kvs {
			lines = append(lines, a.lineToRule(string(kv.Key)))
		}

		for _, line := range lines {
			err := loadPolicyLine(line, model)
			if err != nil {
				return err
			}
		}
	}
	a.isFiltered = true

	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *EtcdAdapter) IsFiltered() bool {
	return a.isFiltered
}

func (a *EtcdAdapter) filterQuery(filter Filter) string {
	prefix := a.getTableInstance()
	if len(filter.PType) > 0 {
		prefix = path.Join(prefix, filter.PType[0])
	}
	if len(filter.V0) > 0 {
		prefix = path.Join(prefix, filter.V0[0])
	}
	if len(filter.V1) > 0 {
		prefix = path.Join(prefix, filter.V1[0])
	}
	if len(filter.V2) > 0 {
		prefix = path.Join(prefix, filter.V2[0])
	}
	if len(filter.V3) > 0 {
		prefix = path.Join(prefix, filter.V3[0])
	}
	if len(filter.V4) > 0 {
		prefix = path.Join(prefix, filter.V4[0])
	}
	if len(filter.V5) > 0 {
		prefix = path.Join(prefix, filter.V5[0])
	}
	return prefix
}

func (a *EtcdAdapter) savePolicyLine(ptype string, rule []string) string {
	line := a.getTableInstance()

	line = path.Join(line, ptype)
	if len(rule) > 0 {
		line = path.Join(line, rule[0])
	}
	if len(rule) > 1 {
		line = path.Join(line, rule[1])
	}
	if len(rule) > 2 {
		line = path.Join(line, rule[2])
	}
	if len(rule) > 3 {
		line = path.Join(line, rule[3])
	}
	if len(rule) > 4 {
		line = path.Join(line, rule[4])
	}
	if len(rule) > 5 {
		line = path.Join(line, rule[5])
	}

	return line
}

func (a *EtcdAdapter) lineToRule(line string) Rule {
	line = strings.TrimPrefix(line, a.getFullTableName())

	rule := Rule{}
	parts := strings.Split(line, "/")
	if len(parts) > 0 {
		rule.PType = parts[0]
	}
	if len(parts) > 1 {
		rule.V0 = parts[1]
	}
	if len(parts) > 2 {
		rule.V1 = parts[2]
	}
	if len(parts) > 3 {
		rule.V2 = parts[3]
	}
	if len(parts) > 4 {
		rule.V3 = parts[3]
	}
	if len(parts) > 5 {
		rule.V4 = parts[4]
	}
	if len(parts) > 6 {
		rule.V5 = parts[5]
	}

	return rule
}

func (a *EtcdAdapter) ruleToLine(rule Rule) string {
	line := a.getTableInstance()

	if rule.PType != "" {
		line = path.Join(line, rule.PType)
	}
	if rule.V0 != "" {
		line = path.Join(line, rule.V0)
	}
	if rule.V1 != "" {
		line = path.Join(line, rule.V1)
	}
	if rule.V2 != "" {
		line = path.Join(line, rule.V2)
	}
	if rule.V3 != "" {
		line = path.Join(line, rule.V3)
	}
	if rule.V4 != "" {
		line = path.Join(line, rule.V4)
	}
	if rule.V5 != "" {
		line = path.Join(line, rule.V5)
	}

	return line
}

// SavePolicy saves policy to database.
func (a *EtcdAdapter) SavePolicy(model model.Model) error {
	if err := a.dropTable(); err != nil {
		return err
	}

	ctx := context.TODO()

	var lines []string
	flushEvery := 1000
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				for _, line := range lines {
					if _, err := a.conn.Put(ctx, line, ""); err != nil {
						return err
					}
				}

				lines = nil
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
			if len(lines) > flushEvery {
				for _, line := range lines {
					if _, err := a.conn.Put(ctx, line, ""); err != nil {
						return err
					}
				}
				lines = nil
			}
		}
	}
	if len(lines) > 0 {
		for _, line := range lines {
			if _, err := a.conn.Put(ctx, line, ""); err != nil {
				return err
			}
		}
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *EtcdAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	_, err := a.conn.Put(context.TODO(), line, "")
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *EtcdAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	err := a.rawDelete(a.lineToRule(line)) //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
	return err
}

// AddPolicies adds multiple policy rules to the storage.
func (a *EtcdAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	var lines []string
	for _, rule := range rules {
		line := a.savePolicyLine(ptype, rule)
		lines = append(lines, line)
	}
	ctx := context.TODO()
	for _, line := range lines {
		_, err := a.conn.Put(ctx, line, "")
		if err != nil {
			return err
		}
	}
	return nil
}

// RemovePolicies removes multiple policy rules from the storage.
func (a *EtcdAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	for _, rule := range rules {
		line := a.savePolicyLine(ptype, rule)
		if err := a.rawDelete(a.lineToRule(line)); err != nil { //can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
			return err
		}
	}
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *EtcdAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := a.lineToRule(a.getTableInstance())

	line.PType = ptype

	if fieldIndex == -1 {
		return a.rawDelete(line)
	}

	err := checkQueryField(fieldValues)
	if err != nil {
		return err
	}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	err = a.rawDelete(line)
	return err
}

func (a *EtcdAdapter) rawDelete(line Rule) error {
	_, err := a.conn.Delete(context.TODO(), a.ruleToLine(line))
	return err
}

// UpdatePolicy updates a new policy rule to DB.
func (a *EtcdAdapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	newLine := a.savePolicyLine(ptype, newPolicy)
	_, err := a.conn.Put(context.TODO(), newLine, "")
	return err
}

func (a *EtcdAdapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	newPolicies := make([]string, 0, len(oldRules))
	for _, newRule := range newRules {
		newPolicies = append(newPolicies, a.savePolicyLine(ptype, newRule))
	}
	ctx := context.TODO()
	for i := range newPolicies {
		if _, err := a.conn.Delete(ctx, newPolicies[i]); err != nil {
			return err
		}
	}

	return nil
}

func (a *EtcdAdapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	// UpdateFilteredPolicies deletes old rules and adds new rules.
	line := Rule{}

	line.PType = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	newP := make([]string, 0, len(newPolicies))
	oldP := make([]Rule, 0)
	for _, newRule := range newPolicies {
		newP = append(newP, a.savePolicyLine(ptype, newRule))
	}

	ctx := context.TODO()
	key := a.ruleToLine(line)
	rsp, err := a.conn.Get(ctx, key, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend))
	if err != nil {
		return nil, err
	}
	for _, kv := range rsp.Kvs {
		rule := a.lineToRule(string(kv.Key))
		oldP = append(oldP, rule)
		_ = a.rawDelete(rule)
	}

	for i := range newP {
		if _, err := a.conn.Put(ctx, newP[i], ""); err != nil {
			return nil, err
		}
	}

	// return deleted rulues
	oldPolicies := make([][]string, 0)
	for _, v := range oldP {
		oldPolicy := v.toStringPolicy()
		oldPolicies = append(oldPolicies, oldPolicy)
	}
	return oldPolicies, nil
}

// Preview Pre-checking to avoid causing partial load success and partial failure deep
func (a *EtcdAdapter) Preview(rules *[][]string, model model.Model) error {
	j := 0
	for i, rule := range *rules {
		r := (*rules)[i]
		index := len(r) - 1
		for r[index] == "" {
			index--
		}
		index += 1
		p := r[:index]
		key := p[0]
		sec := key[:1]
		ok, err := model.HasPolicyEx(sec, key, p[1:])
		if err != nil {
			return err
		}
		if ok {
			(*rules)[j], (*rules)[i] = rule, (*rules)[j]
			j++
		}
	}
	*rules = (*rules)[j:]
	return nil
}
